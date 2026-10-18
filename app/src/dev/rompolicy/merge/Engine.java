package dev.rompolicy.merge;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.channels.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.*;
import org.json.*;

/** Root-only worker. All modifications are restricted to discovered, existing split-policy files. */
public final class Engine {
    final Path job,toolDir;final JSONObject request;final LinkedHashMap<String,byte[]> originals=new LinkedHashMap<>(),candidate=new LinkedHashMap<>();
    final Map<String,String> dirs=new LinkedHashMap<>();final List<Cil.Merger> mergers=new ArrayList<>();
    final Set<String> deletions=new LinkedHashSet<>();final Map<String,Integer> counts=new TreeMap<>();
    final Map<String,Integer> reasons=new TreeMap<>();final JSONObject validation=new JSONObject();
    Path target,source;BufferedWriter audit;int commandId=0,notes=0;String version,compileVersion;boolean committing=false;
    public Engine(Path j,Path tools,JSONObject req){job=j;toolDir=tools;request=req;}
    static byte[] bytes(Path p)throws IOException {long n=Files.size(p);if(n>128L*1024*1024)throw new IOException("File too large: "+p);return Files.readAllBytes(p);}
    static String text(byte[] b){return new String(b,StandardCharsets.UTF_8);}
    static String text(Path p)throws IOException{return text(bytes(p));}
    static String hash(byte[] b)throws Exception{StringBuilder s=new StringBuilder();for(byte x:MessageDigest.getInstance("SHA-256").digest(b))s.append(String.format(Locale.ROOT,"%02x",x&255));return s.toString();}
    static void write(Path p,byte[] b)throws IOException{Files.createDirectories(p.getParent());try(FileOutputStream f=new FileOutputStream(p.toFile())){f.write(b);f.getFD().sync();}}
    static void json(Path p,JSONObject j)throws Exception{Path tmp=p.resolveSibling(p.getFileName()+".tmp");write(tmp,j.toString(2).getBytes(StandardCharsets.UTF_8));Files.move(tmp,p,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
    static void canonical(Path p)throws IOException{if(!p.toAbsolutePath().normalize().equals(p.toRealPath()))throw new IOException("Refusing symlink/alias: "+p);}
    static Path root(String raw)throws IOException {
        Path p=Paths.get(raw.trim());if(!p.isAbsolute())throw new IOException("必须填写绝对解包路径");p=p.normalize();canonical(p);
        String s=p.toString();if(!(s.startsWith("/data/")||s.startsWith("/storage/"))||p.getNameCount()<3||s.startsWith("/data/adb/")||s.startsWith("/data/data/")||s.startsWith("/data/user/"))throw new IOException("拒绝活动系统、模块和宽泛目录；请选择 /data/DNA/你的ROM 这样的独立解包目录");
        if(!Files.isDirectory(p))throw new IOException("不是目录: "+p);return p;
    }
    public void log(String s){System.out.println(s);System.out.flush();}
    void memory(String stage){Runtime r=Runtime.getRuntime();log("内存状态（"+stage+"）：Java 已用 "+(r.totalMemory()-r.freeMemory())/1048576+" MiB，上限 "+r.maxMemory()/1048576+" MiB");}
    void note(String status,String origin,Cil.N n,String why){try{
        counts.merge(status,1,Integer::sum);if(status.equals("SKIPPED")||status.equals("FILTERED")||status.equals("COMPILER_CONFLICT"))reasons.merge(status+": "+why,1,Integer::sum);
        JSONObject r=new JSONObject().put("status",status).put("source",origin).put("reason",why);if(n!=null)r.put("rule",n.text());audit.write(r.toString());audit.newLine();
        if(++notes%5000==0){audit.flush();log("合并进度：已分析 "+notes+" 项，新增 "+counts.getOrDefault("ADDED",0)+"，按设置排除 "+counts.getOrDefault("EXCLUDED",0)+"，不兼容跳过 "+counts.getOrDefault("SKIPPED",0)+"，无效权限处理 "+counts.getOrDefault("FILTERED",0));}
        if(status.equals("FILTERED")&&counts.get(status)<=12)log("权限筛选："+why);
    }catch(Exception e){throw new RuntimeException(e);}}
    String run(List<String> args,int seconds,boolean required)throws Exception{
        Path output=job.resolve(String.format(Locale.ROOT,"commands/%04d-%s.log",++commandId,UUID.randomUUID().toString().substring(0,8)));Files.createDirectories(output.getParent());
        Process p=new ProcessBuilder(args).redirectErrorStream(true).redirectOutput(output.toFile()).start();
        long begin=System.nanoTime(),lastHeartbeat=begin;RuntimeLog.Tailer stream=new RuntimeLog.Tailer(output);int displayed=0;
        boolean finished=false;
        try{
            while(!(finished=p.waitFor(1,TimeUnit.SECONDS))){
                for(String line:stream.poll(false))if(displayed++<120)log(RuntimeLog.translate(line));
                long now=System.nanoTime();
                if(now-begin>=TimeUnit.SECONDS.toNanos(seconds)){p.destroyForcibly();p.waitFor();throw new IOException("命令超时，未继续写回: "+args.get(0));}
                if(now-lastHeartbeat>=TimeUnit.SECONDS.toNanos(10)){log("工作程序仍在运行，已等待 "+TimeUnit.NANOSECONDS.toSeconds(now-begin)+" 秒；请勿同时修改目标文件");lastHeartbeat=now;}
            }
            for(String line:stream.poll(true))if(displayed++<120)log(RuntimeLog.translate(line));
            if(displayed>120)log("编译器输出较多，完整原始输出保存在 "+output.getFileName());
        }finally{if(!finished&&p.isAlive())p.destroyForcibly();}
        String s=text(output);json(output.resolveSibling(output.getFileName()+".json"),new JSONObject().put("argv",new JSONArray(args)).put("exit",p.exitValue()));
        if(required&&p.exitValue()!=0)throw new IOException("命令失败 "+args.get(0)+": "+tail(s,1800));return "EXIT="+p.exitValue()+"\n"+s;
    }
    static String tail(String s,int n){return s.length()>n?s.substring(s.length()-n):s;}
    Map<String,String> discover(Path base)throws Exception{
        return discover(base,true);
    }
    Map<String,String> discover(Path base,boolean requirePlatform)throws Exception{
        Map<String,String> out=new LinkedHashMap<>();
        for(String part:Arrays.asList("system","system_ext","product","vendor","odm")){
            List<String> tryPaths=part.equals("system")?Arrays.asList("system/system/etc/selinux","system/etc/selinux"):Arrays.asList(part+"/etc/selinux");
            for(String rel:tryPaths)if(Files.isDirectory(base.resolve(rel),LinkOption.NOFOLLOW_LINKS)){
                canonical(base.resolve(rel));
                if(part.equals("system")&&!Files.isRegularFile(base.resolve(rel+"/plat_sepolicy.cil"),LinkOption.NOFOLLOW_LINKS))continue;
                out.put(part,rel);break;
            }
        }
        if(!out.containsKey("vendor")||(requirePlatform&&!out.containsKey("system")))throw new IOException(requirePlatform?"目标需要 system 平台 CIL 和 vendor；OTA 模式仍需平台策略参与只读验证":"来源至少需要 vendor/etc/selinux；允许来源缺少 system，不借用或伪造来源平台");
        return out;
    }
    void snapshot()throws Exception{
        long total=0;
        for(String dir:dirs.values())try(java.util.stream.Stream<Path> stream=Files.walk(target.resolve(dir))){
            for(Path p:(Iterable<Path>)stream::iterator){
                canonical(p);if(Files.isDirectory(p))continue;
                String rel=target.relativize(p).toString();if(!Files.isRegularFile(p))throw new IOException("非普通策略文件: "+p);
                if(originals.size()>4096||(total+=Files.size(p))>192L*1024*1024)throw new IOException("策略快照过大，停止以避免内存不足");byte[] b=bytes(p);originals.put(rel,b);candidate.put(rel,b);write(job.resolve("original").resolve(rel),b);
            }
        }
        version=text(originals.getOrDefault(dirs.get("vendor")+"/plat_sepolicy_vers.txt",new byte[0])).trim();
        if(!version.matches("[0-9]{2,6}(?:\\.[0-9]+)?"))throw new IOException("目标 plat_sepolicy_vers.txt 缺失或无效");
        log("目标 vendor SELinux 接口版本："+version+"（不修改版本文件）");
    }
    static String prefix(String part){return part.equals("system")?"plat":part;}
    List<String> inputs(Map<String,String> ds,Set<String> files,String v,boolean debug)throws IOException{
        List<String> r=new ArrayList<>();
        for(String part:Arrays.asList("system","system_ext","product")){
            if(!ds.containsKey(part))continue;String dir=ds.get(part),normal=dir+"/"+prefix(part)+"_sepolicy.cil",f=normal;
            if(debug){String d=dir+"/"+prefix(part)+"_sepolicy_debug.cil";
                if(part.equals("system")&&ds.containsKey("system_ext")&&files.contains(ds.get("system_ext")+"/plat_sepolicy_debug.cil"))d=ds.get("system_ext")+"/plat_sepolicy_debug.cil";
                if(files.contains(d))f=d;
            }
            if(files.contains(f))r.add(f);else if(part.equals("system"))throw new IOException("缺少平台主 CIL: "+f);
            String mapping=dir+"/mapping/"+v+".cil";
            if(files.contains(mapping))r.add(mapping);else if(part.equals("system"))throw new IOException("缺少目标 vendor 对应平台 mapping: "+mapping);
            String compat=dir+"/mapping/"+v+".compat.cil";if(!part.equals("product")&&files.contains(compat))r.add(compat);
        }
        String vd=ds.get("vendor");
        for(String name:Arrays.asList("plat_pub_versioned","vendor_sepolicy")){
            String f=vd+"/"+name+(debug&&files.contains(vd+"/"+name+"_debug.cil")?"_debug":"")+".cil";
            if(files.contains(f))r.add(f);else if(name.equals("vendor_sepolicy"))throw new IOException("缺少 vendor 主 CIL");
        }
        if(ds.containsKey("odm")){String f=ds.get("odm")+"/odm_sepolicy"+(debug&&files.contains(ds.get("odm")+"/odm_sepolicy_debug.cil")?"_debug":"")+".cil";if(files.contains(f))r.add(f);}
        return r;
    }
    void addGenfs(List<String> ins,Map<String,String> ds,Map<String,byte[]> fs){
        String gen=text(fs.getOrDefault(ds.get("vendor")+"/genfs_labels_version.txt","202404".getBytes(StandardCharsets.UTF_8))).trim();
        String file=ds.get("system")+"/plat_sepolicy_genfs_"+gen+".cil";if(fs.containsKey(file))ins.add(file);
    }
    String destination(String srcPart,boolean debug)throws IOException{
        if(request.optString("write_scope","all").equals("vendor_odm")&&!Arrays.asList("vendor","odm").contains(srcPart))srcPart="vendor";
        String part=dirs.containsKey(srcPart)?srcPart:"vendor";String f=dirs.get(part)+"/"+prefix(part)+"_sepolicy.cil";
        if(debug){String d=dirs.get(part)+"/"+prefix(part)+"_sepolicy_debug.cil";
            if(part.equals("system")&&dirs.containsKey("system_ext")&&originals.containsKey(dirs.get("system_ext")+"/plat_sepolicy_debug.cil"))d=dirs.get("system_ext")+"/plat_sepolicy_debug.cil";
            if(originals.containsKey(d))f=d;
        }
        if(!originals.containsKey(f)){if(!part.equals("vendor"))return destination("vendor",debug);throw new IOException("没有可安全追加的目标 CIL");}return f;
    }
    String variantDestination(String part,boolean debug)throws IOException{
        String dest=destination(part,debug);
        List<String> normal=inputs(dirs,originals.keySet(),version,false);
        List<String> dbg=inputs(dirs,originals.keySet(),version,true);
        if(normal.equals(dbg))return dest;
        List<String> chosen=debug?dbg:normal,other=debug?normal:dbg;
        if(!other.contains(dest))return dest;
        // Shared files feed both variants. Either variant's additions can reference
        // types that exist only in its own platform file. Keep BOTH directions isolated.
        String vendor=dirs.get("vendor")+"/vendor_sepolicy"+(debug?"_debug":"")+".cil";
        if(chosen.contains(vendor)&&!other.contains(vendor))return vendor;
        for(String f:chosen)if(writable(f)&&f.endsWith(debug?"_sepolicy_debug.cil":"_sepolicy.cil")&&!other.contains(f))return f;
        throw new IOException("目标没有可独立承载本变体新增规则的 CIL，停止以免普通/debug 策略相互污染");
    }
    Map<String,byte[]> readSource(Map<String,String> ds)throws Exception{
        Map<String,byte[]> all=new LinkedHashMap<>();long total=0;
        for(String dir:ds.values())try(java.util.stream.Stream<Path> st=Files.walk(source.resolve(dir))){
            for(Path p:(Iterable<Path>)st::iterator){canonical(p);if(Files.isDirectory(p))continue;if(!Files.isRegularFile(p))throw new IOException("来源含特殊文件");String n=p.getFileName().toString();if(n.endsWith(".cil")||n.endsWith("_contexts")||n.endsWith("version.txt")||n.equals("plat_sepolicy_vers.txt")){
                if(all.size()>=4096||(total+=Files.size(p))>192L*1024*1024)throw new IOException("来源策略快照过大");
                String rel=source.relativize(p).toString();byte[] data=bytes(p);all.put(rel,data);write(job.resolve("source").resolve(rel),data);
            }}
        }return all;
    }
    static final class PolicySource {
        final Map<String,String> dirs=new LinkedHashMap<>();
        final Map<String,byte[]> files=new LinkedHashMap<>();
    }
    static boolean devicePolicyFile(String n){
        return !n.startsWith("precompiled_")&&(n.endsWith(".cil")||kind(n)!=null||n.equals("plat_sepolicy_vers.txt")||n.equals("genfs_labels_version.txt"));
    }
    PolicySource readDevicePolicy()throws Exception{
        PolicySource out=new PolicySource();JSONArray manifest=new JSONArray();long total=0;
        for(String part:Arrays.asList("system","system_ext","product","vendor","odm")){
            Path dir=Paths.get("/"+part+"/etc/selinux");
            if(!Files.isDirectory(dir))continue;
            String rel=part+"/etc/selinux";out.dirs.put(part,rel);
            // Read the mounted partition view, including mapping subdirectories. A partition
            // root may itself be a legitimate system symlink; never follow file links out of it.
            Path resolved=dir.toRealPath();int count=0;long partBytes=0;
            try(java.util.stream.Stream<Path> files=Files.walk(resolved)){
                for(Path p:(Iterable<Path>)files::iterator){
                    if(Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS))continue;
                    if(!devicePolicyFile(p.getFileName().toString()))continue;
                    canonical(p);if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))throw new IOException("手机分区策略不是普通文件: "+p);
                    if(out.files.size()>=4096||(total+=Files.size(p))>192L*1024*1024)throw new IOException("手机分区策略快照过大，停止；不回退读取内核策略");
                    String name=rel+"/"+resolved.relativize(p);byte[] b=bytes(p);out.files.put(name,b);write(job.resolve("device-partitions").resolve(name),b);
                    manifest.put(new JSONObject().put("source","/"+name).put("resolved",p.toString()).put("bytes",b.length).put("sha256",hash(b)));count++;partBytes+=b.length;
                }
            }
            log("手机分区快照：/"+rel+"，"+count+" 个文件，"+partBytes+" 字节");
        }
        if(!out.dirs.containsKey("system")||!out.dirs.containsKey("vendor"))throw new IOException("手机缺少 system/vendor 分区 CIL，不能作为来源；不会读取内核策略代替");
        String v=text(out.files.getOrDefault(out.dirs.get("vendor")+"/plat_sepolicy_vers.txt",new byte[0])).trim();
        if(!v.matches("[0-9]{2,6}(?:\\.[0-9]+)?"))throw new IOException("手机分区缺少有效的 plat_sepolicy_vers.txt；不回退导出内核策略");
        inputs(out.dirs,out.files.keySet(),v,false);
        json(job.resolve("device-partitions.json"),new JSONObject().put("source_kind","mounted_partition_files").put("kernel_policy_read",false).put("vendor_interface",v).put("files",manifest));
        log("手机分区策略快照完成，接口 "+v+"；不读取 /sys/fs/selinux/policy，不导入内核动态注入规则");
        return out;
    }
    void stageCil()throws Exception{
        for(String rel:originals.keySet())if(rel.endsWith(".cil")){
            StringBuilder b=new StringBuilder(text(originals.get(rel)));boolean any=false;
            Set<String> seen=new HashSet<>();for(Cil.Merger m:mergers)for(Cil.Entry e:m.additions)if(e.active&&e.path.equals(rel)&&seen.add(e.node.text())){if(!any){b.append("\n; ROM Policy Merge: additions, original prefix preserved\n");any=true;}b.append(e.node.text()).append('\n');}
            candidate.put(rel,any?b.toString().getBytes(StandardCharsets.UTF_8):originals.get(rel));
        }
        for(Map.Entry<String,byte[]> e:candidate.entrySet())write(job.resolve("candidate").resolve(e.getKey()),e.getValue());
    }
    Cil.Index index(boolean debug)throws Exception{
        Cil.Index i=new Cil.Index();List<String> ins=inputs(dirs,candidate.keySet(),version,debug);addGenfs(ins,dirs,candidate);
        for(String p:ins)Cil.parse(text(candidate.get(p)),i::add);return i;
    }
    Cil.Index contextIndex()throws Exception{
        return contextIndex(false);
    }
    Cil.Index contextIndex(boolean debug)throws Exception{
        Cil.Index i=new Cil.Index();List<String> ins=inputs(dirs,candidate.keySet(),version,debug);addGenfs(ins,dirs,candidate);
        // Context validation needs concrete type/alias names, not 400k access rules.
        for(String p:ins)Cil.parse(text(candidate.get(p)),n->{if(n.head().equals("type")||n.head().equals("typealiasactual"))i.add(n);});return i;
    }
    void mergeSource(Cil.Merger m,Map<String,String> sd,Map<String,byte[]> sf,boolean debug,String namespace,String originPrefix)throws Exception{
        String sv=text(sf.getOrDefault(sd.get("vendor")+"/plat_sepolicy_vers.txt",new byte[0])).trim();
        if(!sv.matches("[0-9]{2,6}(?:\\.[0-9]+)?"))throw new IOException("来源缺少有效 plat_sepolicy_vers.txt: "+originPrefix);
        List<String> src=inputs(sd,sf.keySet(),sv,debug);addGenfs(src,sd,sf);
        if(debug&&request.optBoolean("repair_debug",true)){
            // Only device-side ordinary policy supplements debug. Platform variants stay isolated.
            for(String p:inputs(sd,sf.keySet(),sv,false))if(ContextPriority.device(p,sd)&&!src.contains(p))src.add(p);
        }
        mergeFiles(m,sd,sf,src,debug,namespace,originPrefix);
    }
    void mergeFiles(Cil.Merger m,Map<String,String> sd,Map<String,byte[]> sf,List<String> src,boolean debug,String namespace,String originPrefix)throws Exception{
        List<Cil.Entry> blocks=new ArrayList<>();
        // All declarations are processed before rules, across all source partitions.
        // Generated attributes get per-file namespaces before the global merge.
        for(String p:src){String part="vendor";for(Map.Entry<String,String> d:sd.entrySet())if(p.startsWith(d.getValue()+"/")){part=d.getKey();break;}
            String dest=variantDestination(part,debug);List<Cil.N> nodes=Cil.parse(text(sf.get(p)));Map<String,String> rename=new HashMap<>();
            // Different ROMs reuse both file paths and generated attribute numbers.
            // Fingerprint the generated membership graph, not the entire file: imported
            // additions must not rename the target's original attributes on a repeat repair.
            // Sorting also makes source statement order irrelevant to the namespace.
            Set<String> generated=new HashSet<>();
            for(Cil.N n:nodes)if(n.head().equals("typeattribute")&&Cil.GENERATED.matcher(n.s(1)).matches())generated.add(n.s(1));
            Set<String> definitions=new TreeSet<>();
            for(Cil.N n:nodes)if((n.head().equals("typeattribute")||n.head().equals("typeattributeset"))&&generated.contains(n.s(1)))definitions.add(n.text());
            String fileId=hash((p+"\n"+String.join("\n",definitions)).getBytes(StandardCharsets.UTF_8));
            for(Cil.N n:nodes)if(n.head().equals("typeattribute")&&Cil.GENERATED.matcher(n.s(1)).matches())rename.put(n.s(1),"rpm_"+namespace+"_"+fileId+"_"+n.s(1));
            for(Cil.N n:nodes)blocks.add(new Cil.Entry(dest,originPrefix+p,n.map(s->rename.getOrDefault(s,s))));
        }
        m.merge(blocks,namespace+(debug?"debug":"normal"));
    }
    void mergeVariant(Map<String,String> sd,Map<String,byte[]> sf,boolean debug,PolicySource device)throws Exception{
        Cil.Index idx=index(debug);Cil.Merger m=new Cil.Merger(idx,this::note);m.permissive=request.optBoolean("permissive");m.hardwareLabels=request.optBoolean("hardware");m.targetVersion=version.replace(".","_");mergers.add(m);
        if(debug&&request.optBoolean("repair_debug",true)){
            // The current target may already contain a prior Xiaomi merge. Preserve it as the baseline.
            List<String> selected=inputs(dirs,originals.keySet(),version,true),supplement=new ArrayList<>();
            for(String p:inputs(dirs,originals.keySet(),version,false))if(ContextPriority.device(p,dirs)&&!selected.contains(p))supplement.add(p);
            log("debug 补齐：读取当前目标及来源的普通 vendor/odm 规则；不将 debug 专用规则反灌普通版");
            mergeFiles(m,dirs,originals,supplement,true,"targetnormal","目标普通版:");
        }
        mergeSource(m,sd,sf,debug,"src","");
        if(device!=null){log("合并手机五分区 CIL，优先按分区归属；普通/debug 专用新增隔离存放，不导入展开后的整机运行策略");mergeSource(m,device.dirs,device.files,debug,"device","手机分区:/");}
        if(request.has("extra")&&!request.optString("extra").isEmpty()){
            Path extra=Paths.get(request.getString("extra"));canonical(extra);
            memory("额外规则解析前");
            // ExtraRules only reads this index; do not duplicate the full policy here.
            List<Cil.N> parsed=new ExtraRules(idx).parse(text(extra),request.optString("format","auto"));List<Cil.Entry> e=new ArrayList<>();
            for(Cil.N n:parsed)e.add(new Cil.Entry(variantDestination("vendor",debug),"用户额外规则",n));int skipped=counts.getOrDefault("SKIPPED",0),filtered=counts.getOrDefault("FILTERED",0);m.merge(e,"extra");
            log("额外规则筛选完成：目标不支持而跳过 "+(counts.getOrDefault("SKIPPED",0)-skipped)+" 项，排除无效权限 "+(counts.getOrDefault("FILTERED",0)-filtered)+" 项；有效规则保留，继续完整编译");
        }
        // Only additions are needed for compiler conflict rollback. Do not retain a second
        // complete policy symbol/text index while building the debug variant.
        idx.release();stageCil();memory(debug?"debug 合并完成":"普通合并完成");log((debug?"debug":"普通")+"策略已生成，新增 CIL 块 "+m.additions.size());
    }
    static String kind(String file){
        for(String k:Arrays.asList("property_contexts","file_contexts","hwservice_contexts","vndservice_contexts","tee_service_contexts","service_contexts","seapp_contexts","keystore2_key_contexts"))if(file.endsWith(k))return k;return null;
    }
    static List<String> lines(byte[] b){List<String> r=new ArrayList<>();for(String line:text(b).split("\\r?\\n")){String s=line.replaceFirst("\\s+#.*$", "").trim();if(!s.isEmpty()&&!s.startsWith("#"))r.add(s);}return r;}
    static String contextKey(String line,String kind){
        String[] t=line.split("\\s+");
        if(kind.equals("file_contexts"))return t[0]+(t.length>2?" "+t[1]:"");
        if(kind.equals("seapp_contexts")){List<String> k=new ArrayList<>();for(String s:t)if(!s.matches("(?:domain|type|level|levelFrom)=.*"))k.add(s);Collections.sort(k);return String.join(" ",k);}
        return t[0]+(kind.equals("property_contexts")?"|"+(t.length>2?t[2]:"prefix"):"");
    }
    static boolean contextTypesExist(String line,Cil.Index idx){
        Matcher refs=Pattern.compile("\\bu:[^:\\s]+:([^:\\s]+):").matcher(line);
        while(refs.find())if(!idx.types.contains(refs.group(1))&&!idx.aliases.containsKey(refs.group(1)))return false;
        return true;
    }
    boolean writable(String rel){
        return !request.optString("write_scope","all").equals("vendor_odm")||ContextPriority.device(rel,dirs);
    }
    String contextDestination(String part,String filename,String kind){
        String same=dirs.containsKey(part)?dirs.get(part)+"/"+filename:null;
        if(same!=null&&writable(same)&&candidate.containsKey(same))return same;
        if(!request.optString("write_scope","all").equals("vendor_odm"))return null;
        for(String device:Arrays.asList("vendor","odm"))if(dirs.containsKey(device)){
            String p=dirs.get(device)+"/"+device+"_"+kind;if(candidate.containsKey(p))return p;
            p=dirs.get(device)+"/"+kind;if(candidate.containsKey(p))return p;
        }
        return null;
    }
    void mergeContexts(Map<String,String> sd,Map<String,byte[]> sf)throws Exception{
        ContextPriority.resolve(candidate,dirs,this::note);
        Cil.Index idx=contextIndex();Map<String,Map<String,String>> existing=new HashMap<>();
        Map<String,Map<String,String>> owners=new HashMap<>();boolean targetPropertyConflict=false;
        for(Map.Entry<String,byte[]> e:candidate.entrySet()){
            String k=kind(e.getKey());if(k==null||e.getKey().contains("/precompiled_"))continue;
            Map<String,String> seen=existing.computeIfAbsent(k,z->new HashMap<>());
            Map<String,String> own=owners.computeIfAbsent(k,z->new HashMap<>());
            for(String l:lines(e.getValue())){
                if(l.startsWith("neverallow"))continue;
                String key=contextKey(l,k),old=seen.putIfAbsent(key,l);String oldFile=own.putIfAbsent(key,e.getKey());
                if(old!=null&&!old.replaceAll("\\s+"," ").equals(l.replaceAll("\\s+"," "))){
                    note("CONTEXT_TARGET_CONFLICT",e.getKey(),null,l+" -> "+oldFile+": "+old);
                    // Cross platform/device conflicts were resolved above. Remaining conflicts
                    // within a side are reported rather than guessed from partition order.
                    if(k.equals("property_contexts"))targetPropertyConflict=true;
                }
            }
        }
        if(targetPropertyConflict)throw new IOException("目标原有 property_contexts 存在重复键冲突，已记入日志；本次未写回");
        for(Map.Entry<String,String> part:sd.entrySet())for(Map.Entry<String,byte[]> e:sf.entrySet()){
            if(!e.getKey().startsWith(part.getValue()+"/"))continue;String k=kind(e.getKey());if(k==null||e.getKey().contains("/precompiled_"))continue;
            if((k.equals("file_contexts"))&&!request.optBoolean("hardware")){note("SKIPPED",e.getKey(),null,"硬件/文件标签默认保守；开启高级硬件标签选项才导入");continue;}
            String dest=contextDestination(part.getKey(),Paths.get(e.getKey()).getFileName().toString(),k);
            if(dest==null){note("SKIPPED",e.getKey(),null,"写入范围内没有此类正式上下文文件，不新建未经 init 识别的文件");continue;}
            Map<String,String> seen=existing.computeIfAbsent(k,z->new HashMap<>());StringBuilder b=new StringBuilder(text(candidate.get(dest)));int added=0;
            for(String line:lines(e.getValue())){
                String key=contextKey(line,k);String old=seen.get(key);
                if(old!=null){
                    boolean conflict=!old.replaceAll("\\s+"," ").equals(line.replaceAll("\\s+"," "));
                    boolean platformWins=conflict&&ContextPriority.platform(dest,dirs)&&ContextPriority.device(owners.getOrDefault(k,Collections.emptyMap()).get(key),dirs);
                    if(conflict)note("CONTEXT_CONFLICT",e.getKey(),null,line+(platformWins?" -> 平台优先，验证后移除 vendor/odm 项: ":" -> 保留 ")+owners.getOrDefault(k,Collections.emptyMap()).get(key)+": "+old);
                    if(!platformWins)continue;
                }
                if(line.startsWith("neverallow")){note("SKIPPED",e.getKey(),null,"不导入 seapp 断言");continue;}
                Set<String> refs=new HashSet<>();Matcher labels=Pattern.compile("\\bu:[^:\\s]+:([^:\\s]+):").matcher(line);while(labels.find())refs.add(labels.group(1));
                if(k.equals("seapp_contexts")){Matcher mm=Pattern.compile("(?:^|\\s)(?:domain|type)=(\\S+)").matcher(line);while(mm.find())refs.add(mm.group(1));}
                if(!refs.stream().allMatch(t->idx.types.contains(t)||idx.aliases.containsKey(t))){note("SKIPPED",e.getKey(),null,"上下文类型未定义: "+line);continue;}
                if(k.equals("property_contexts")){
                    String[] fields=line.split("\\s+");if(fields.length<2||fields.length>3&&!Arrays.asList("exact","prefix").contains(fields[2]))throw new IOException("来源属性上下文格式异常: "+line);
                    // Do not introduce a duplicate prefix differing only by legacy implicit prefix notation.
                    if(old==null&&seen.containsKey(fields[0]+"|prefix")&&!(fields.length>2&&fields[2].equals("exact"))){note("CONTEXT_CONFLICT",e.getKey(),null,"重复属性前缀: "+line);continue;}
                }
                if(k.equals("file_contexts")){try{Pattern.compile(line.split("\\s+")[0]);}catch(Exception ex){note("SKIPPED",e.getKey(),null,"无法验证的文件标签正则: "+line);continue;}}
                b.append('\n').append(line);seen.put(key,line);owners.computeIfAbsent(k,z->new HashMap<>()).put(key,dest);added++;note("CONTEXT_ADDED",e.getKey(),null,line);
            }
            if(added>0)candidate.put(dest,b.append('\n').toString().getBytes(StandardCharsets.UTF_8));
        }
        ContextPriority.resolve(candidate,dirs,this::note);
        // ODM's premerged text caches must describe the same final partition contexts.
        for(String part:Arrays.asList("odm","vendor"))if(dirs.containsKey(part))for(String k:Arrays.asList("file_contexts","property_contexts","service_contexts")){
            String cache=dirs.get(part)+"/precompiled_"+k;if(!candidate.containsKey(cache))continue;
            if(text(candidate.get(cache)).indexOf('\0')>=0)throw new IOException("不支持的二进制 contexts 缓存，不冒险覆盖: "+cache);
            // Preserve the target cache's original precedence and bytes; append missing keys.
            LinkedHashMap<String,String> all=new LinkedHashMap<>();StringBuilder cleaned=new StringBuilder();boolean added=false;
            // Precompiled text is a derivative cache, not a source of missing type declarations.
            // Cached entries from the replaced platform must not keep undefined old types alive.
            for(String raw:text(candidate.get(cache)).split("\\r?\\n",-1)){
                List<String> content=lines(raw.getBytes(StandardCharsets.UTF_8));String line=content.isEmpty()?"":content.get(0);
                if(!line.isEmpty()&&!contextTypesExist(line,idx)){note("CONTEXT_CACHE_INVALID",cache,null,"移除缓存中的未定义标签（正式 contexts 不删除）: "+line);added=true;continue;}
                if(!line.isEmpty())all.putIfAbsent(contextKey(line,k),line);cleaned.append(raw).append('\n');
            }
            StringBuilder merged=added?cleaned:new StringBuilder(text(candidate.get(cache)));
            for(Map.Entry<String,byte[]> e:candidate.entrySet())if(k.equals(kind(e.getKey()))&&!e.getKey().contains("/precompiled_"))for(String line:lines(e.getValue())){
                String key=contextKey(line,k);String old=all.putIfAbsent(key,line);
                if(old==null){merged.append('\n').append(line);added=true;}
                else if(!old.replaceAll("\\s+"," ").equals(line.replaceAll("\\s+"," ")))note("CONTEXT_CACHE_CONFLICT",e.getKey(),null,line+" -> 保留 "+cache+": "+old);
            }
            if(added)candidate.put(cache,merged.append('\n').toString().getBytes(StandardCharsets.UTF_8));
        }
        stageCil();
    }
    boolean compile(boolean debug,int pass)throws Exception{
        String variant=debug?"debug":"normal";
        JSONObject status=new JSONObject().put("pass",pass).put("compiled",false).put("contexts_valid",false);
        validation.put(variant,status);json(job.resolve("validation.json"),validation);
        List<String> ins=inputs(dirs,candidate.keySet(),version,debug);addGenfs(ins,dirs,candidate);
        Path binary=job.resolve(debug?"validated-debug.policy":"validated.policy");String policyVersion=selectCompileVersion();
        status.put("inputs",new JSONArray(ins)).put("stage","compile").put("policy_version",policyVersion).put("neverallow_checked",false);
        json(job.resolve("validation.json"),validation);
        List<String> cmd=new ArrayList<>(Arrays.asList(toolDir.resolve("libsecilc.so").toString(),"-v","-v","-m","-M","true","-G","-N","-c",policyVersion,"-o",binary.toString(),"-f",job.resolve("compiled_file_contexts"+(debug?"-debug":"")).toString()));
        for(String p:ins)cmd.add(job.resolve("candidate").resolve(p).toString());
        log("完整 "+(debug?"debug":"普通")+" 策略编译，第 "+pass+" 次（-N 不检查 neverallow）");String result=run(cmd,request.optBoolean("live")?900:240,false);
        if(!result.startsWith("EXIT=0\n")){
            for(Cil.Merger m:mergers)if(m.resolveTransitionConflict(result)){stageCil();return false;}
            throw new IOException(variant+" 完整策略编译失败，目标未写入。"+tail(result,2800));
        }
        status.put("compiled",true).put("stage","readback");json(job.resolve("validation.json"),validation);
        run(Arrays.asList(toolDir.resolve("libpolicytool.so").toString(),"check",binary.toString()),90,true);
        run(Arrays.asList(toolDir.resolve("libpolicytool.so").toString(),"roundtrip",binary.toString(),binary.toString()+".roundtrip"),90,true);
        Set<String> contexts=new TreeSet<>();for(Map.Entry<String,byte[]> e:candidate.entrySet())if(kind(e.getKey())!=null)for(String line:lines(e.getValue())){
            if(line.startsWith("neverallow"))continue;
            Matcher m=Pattern.compile("\\bu:[^\\s]+:[^\\s]+").matcher(line);while(m.find())contexts.add(m.group());
        }
        status.put("roundtrip",true).put("contexts",contexts.size()).put("stage","contexts");json(job.resolve("validation.json"),validation);
        Path list=job.resolve("contexts-to-check-"+variant+".txt");write(list,(String.join("\n",contexts)+"\n").getBytes(StandardCharsets.UTF_8));
        String checked=run(Arrays.asList(toolDir.resolve("libpolicytool.so").toString(),"contexts",binary.toString(),list.toString()),90,false);
        status.put("contexts_valid",checked.startsWith("EXIT=0\n")).put("stage",checked.startsWith("EXIT=0\n")?"complete":"contexts_failed");json(job.resolve("validation.json"),validation);
        if(!checked.startsWith("EXIT=0\n")){
            Set<String> invalid=new TreeSet<>();Matcher bad=Pattern.compile("(?m)^INVALID_CONTEXT (\\S+)").matcher(checked);while(bad.find())invalid.add(bad.group(1));
            writeContextDiagnosis(variant,invalid,checked);
            throw new IOException(variant+" 标签校验失败："+invalid.size()+" 个无效标签（去重）；不删除正式标签、不伪造空 type。详见 contexts-invalid-"+variant+".json；另一套策略的声明不代表本套已定义。\n"+tail(checked,1200));
        }
        log(variant+"：编译、二进制回读和 "+contexts.size()+" 个标签均通过");return true;
    }
    void writeContextDiagnosis(String variant,Set<String> invalid,String output)throws Exception{
        Cil.Index normal=contextIndex(false),debug=contextIndex(true);JSONArray rows=new JSONArray();
        for(Map.Entry<String,byte[]> e:candidate.entrySet())if(kind(e.getKey())!=null){
            int lineNo=0;for(String raw:text(e.getValue()).split("\\r?\\n",-1)){
                lineNo++;for(String context:invalid)if(raw.contains(context)){
                    String[] fields=context.split(":");String type=fields.length>2?fields[2]:"";
                    rows.put(new JSONObject().put("file",e.getKey()).put("line",lineNo).put("context",context)
                        .put("type",type).put("normal_cil_declares",normal.types.contains(type)||normal.aliases.containsKey(type))
                        .put("debug_cil_declares",debug.types.contains(type)||debug.aliases.containsKey(type)));
                }
            }
        }
        json(job.resolve("contexts-invalid-"+variant+".json"),new JSONObject().put("variant",variant).put("invalid",new JSONArray(invalid)).put("references",rows).put("validator_output",output));
    }
    String selectCompileVersion()throws Exception{
        if(compileVersion!=null)return compileVersion;
        String requested=request.optString("policy_version","");
        if(!requested.isEmpty()){
            if(!requested.matches("(?:2[6-9]|3[0-3])"))throw new IOException("不支持的策略二进制版本: "+requested);
            compileVersion=requested;log("验证使用手选二进制版本 "+compileVersion);return compileVersion;
        }
        for(String rel:originals.keySet())if(rel.endsWith("/precompiled_sepolicy")){
            String result=run(Arrays.asList(toolDir.resolve("libpolicytool.so").toString(),"check",job.resolve("original").resolve(rel).toString()),90,false);
            Matcher m=Pattern.compile("policy_version=([0-9]+)").matcher(result);
            if(result.startsWith("EXIT=0\n")&&m.find()){compileVersion=m.group(1);log("从目标预编译策略读取二进制版本 "+compileVersion+"，不采用当前手机的版本");return compileVersion;}
        }
        compileVersion="33";log("目标无可读预编译策略，验证暂用二进制版本 33；旧内核可在高级选项手动指定。这不是 Android SDK 或 mapping 版本。");return compileVersion;
    }
    void unchanged()throws Exception{for(Map.Entry<String,byte[]> e:originals.entrySet()){Path p=target.resolve(e.getKey());canonical(p);if(!hash(bytes(p)).equals(hash(e.getValue())))throw new IOException("目标文件被其他工具修改，停止覆盖: "+p);}}
    void commit()throws Exception{
        LinkedHashMap<String,byte[]> changes=new LinkedHashMap<>();for(Map.Entry<String,byte[]> e:candidate.entrySet())if(!Arrays.equals(originals.get(e.getKey()),e.getValue()))changes.put(e.getKey(),e.getValue());
        if(changes.isEmpty()){unchanged();log("没有有效新增，目标保持不变");return;}
        for(String p:changes.keySet())if(!writable(p))throw new IOException("拒绝越过写入范围: "+p);
        for(String p:originals.keySet())if(writable(p)&&p.matches(".*?/precompiled_sepolicy(?:_debug)?"))deletions.add(p);
        if(request.optBoolean("validate_only")){unchanged();log("仅验证模式：候选已通过，未写回；计划修改 "+changes.size()+" 个文件，移出 "+deletions.size()+" 个旧二进制缓存");return;}
        unchanged();JSONArray list=new JSONArray();
        // Back up with cp -a as well as byte snapshots, preserving actual unpacked owner/mode/xattrs.
        Set<String> paths=new LinkedHashSet<>(changes.keySet());paths.addAll(deletions);
        for(String rel:paths){Path p=target.resolve(rel),bak=job.resolve("restore").resolve(rel);Files.createDirectories(bak.getParent());run(Arrays.asList("/system/bin/cp","-a",p.toString(),bak.toString()),30,true);
            if(!hash(bytes(bak)).equals(hash(originals.get(rel))))throw new IOException("备份校验失败: "+rel);
            JSONObject row=new JSONObject().put("path",rel).put("before",hash(originals.get(rel))).put("after",deletions.contains(rel)?JSONObject.NULL:hash(changes.get(rel)));
            if(!deletions.contains(rel))row.put("staging",rel+".rpm-"+UUID.randomUUID());
            list.put(row);
        }
        JSONObject manifest=new JSONObject().put("target",target.toString()).put("files",list).put("status","ready").put("committed",new JSONArray());json(job.resolve("transaction.json"),manifest);
        unchanged();committing=true;log("所有验证通过，开始写回 "+paths.size()+" 项（含旧预编译缓存移出）");
        try{
            for(int i=0;i<list.length();i++){
                JSONObject row=list.getJSONObject(i);String rel=row.getString("path");Path p=target.resolve(rel);canonical(p);canonical(p.getParent());
                if(!hash(bytes(p)).equals(row.getString("before")))throw new IOException("写入前文件已变化: "+rel);
                // Journal BEFORE the atomic change; restore tolerates either old or new content after interruption.
                manifest.getJSONArray("committed").put(rel);manifest.put("status","writing");json(job.resolve("transaction.json"),manifest);
                if(row.isNull("after")){
                    // A verified cp -a backup already exists. Do not rename across filesystems:
                    // ROMs on emulated storage and the app's private job have different mounts.
                    Files.delete(p);
                }
                else{
                    Path tmp=target.resolve(row.getString("staging"));
                    if(Files.exists(tmp,LinkOption.NOFOLLOW_LINKS))throw new IOException("暂存路径已被占用: "+tmp);
                    run(Arrays.asList("/system/bin/cp","-a",p.toString(),tmp.toString()),30,true);write(tmp,changes.get(rel));
                    if(!hash(bytes(tmp)).equals(row.getString("after")))throw new IOException("暂存哈希错误");Files.move(tmp,p,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
                }
                log("已处理 "+rel);
            }
            for(int i=0;i<list.length();i++){JSONObject r=list.getJSONObject(i);Path p=target.resolve(r.getString("path"));if(r.isNull("after")){if(Files.exists(p))throw new IOException("旧缓存仍存在");}else if(!hash(bytes(p)).equals(r.getString("after")))throw new IOException("写回校验失败");}
            run(Arrays.asList("/system/bin/sync"),30,true);manifest.put("status","complete");json(job.resolve("transaction.json"),manifest);
        }catch(Exception e){log("写回失败，开始回滚："+e.getMessage());restore(job,toolDir);throw e;}finally{committing=false;}
    }
    public void execute()throws Exception{
        if(Files.exists(job.resolve("transaction.json"))||Files.exists(job.resolve("original")))throw new IOException("任务目录已有快照或事务，请创建新任务；不能覆盖旧备份");
        Files.createDirectories(job);audit=Files.newBufferedWriter(job.resolve("audit.jsonl"),StandardCharsets.UTF_8);
        try{
            if(!Arrays.asList("all","vendor_odm").contains(request.optString("write_scope","all")))throw new IOException("未知写入范围");
            target=root(request.getString("target"));source=root(request.getString("source"));
            if(target.startsWith(source)||source.startsWith(target))throw new IOException("目标和来源不能相同或互相包含");
            dirs.putAll(discover(target));Map<String,String> sd=discover(source,false);log("扫描当前目标策略，来源保持只读；写入范围："+request.optString("write_scope","all"));snapshot();Map<String,byte[]> sf=readSource(sd);
            json(job.resolve("discovery.json"),new JSONObject().put("target",new JSONObject(dirs)).put("source",new JSONObject(sd)).put("source_has_platform",sd.containsKey("system")));
            if(!sd.containsKey("system"))log("来源没有 system：仅读取来源现有分区；使用目标完整平台校验引用，不复制平台、不导出运行内核");
            if(request.has("extra")&&!request.optString("extra").isEmpty()){
                Path extra=Paths.get(request.getString("extra"));canonical(extra);Path snap=job.resolve("extra-snapshot.rule");write(snap,bytes(extra));request.put("extra",snap.toString());
            }
            PolicySource device=null;
            if(request.optBoolean("live")){
                log("只读采集手机 system/system_ext/product/vendor/odm 分区文件；不导出运行时策略。若文件已被模块挂载替换，读到的是当前可见文件。");device=readDevicePolicy();
            }
            boolean debug=!inputs(dirs,originals.keySet(),version,false).equals(inputs(dirs,originals.keySet(),version,true));
            mergeVariant(sd,sf,false,device);if(debug)mergeVariant(sd,sf,true,device);mergeContexts(sd,sf);
            if(device!=null){log("当前手机分区 contexts 快照也进入同一冲突检测流程");mergeContexts(device.dirs,device.files);}
            boolean ok=false;for(int retry=1;retry<=24;retry++){boolean normal=compile(false,retry);boolean dbg=!debug||compile(true,retry);if(normal&&dbg){ok=true;break;}}
            if(!ok)throw new IOException("冲突超过自动处理上限；没有写回");
            commit();log(request.optBoolean("validate_only")?"仅验证完成，目标未写回。候选与详细报告："+job:"完成。只修改了解包目录，未刷入、未重启。备份与详细报告："+job);
        }finally{
            if(audit!=null){audit.flush();audit.close();}
            json(job.resolve("summary.json"),new JSONObject().put("counts",new JSONObject(counts)).put("issues",new JSONObject(reasons)).put("validation",validation)
                .put("target",String.valueOf(target)).put("source",String.valueOf(source)).put("write_scope",request.optString("write_scope","all"))
                .put("repair_debug",request.optBoolean("repair_debug",true)).put("validate_only",request.optBoolean("validate_only"))
                .put("vendor_interface",version).put("neverallow_checked",false).put("kernel_policy_read",false).put("boot_guaranteed",false));
            if(!reasons.isEmpty())log("有 "+counts.getOrDefault("SKIPPED",0)+" 项跳过、"+counts.getOrDefault("FILTERED",0)+" 项权限筛选；不是全部无损合并，详见 summary.json 和 audit.jsonl");
        }
    }
    static Path stagedPath(Path root,JSONObject row,String field)throws Exception{
        if(!row.has(field))return null;String rel=row.getString("path"),name=row.getString(field);
        String prefix=rel+(field.equals("restore_staging")?".rpm-restore-":".rpm-");
        if(!name.startsWith(prefix)||!name.substring(prefix.length()).matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"))throw new IOException("非法暂存文件记录: "+name);
        Path p=root.resolve(name).normalize();
        if(!p.startsWith(root)||!p.getParent().equals(root.resolve(rel).normalize().getParent()))throw new IOException("暂存文件越过目标目录");
        canonical(p.getParent());
        if(Files.exists(p,LinkOption.NOFOLLOW_LINKS)){canonical(p);if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS))throw new IOException("暂存文件不是普通文件: "+p);}
        return p;
    }
    public static void restore(Path job,Path tools)throws Exception{
        JSONObject m=new JSONObject(text(job.resolve("transaction.json")));Path root=root(m.getString("target"));JSONArray rows=m.getJSONArray("files"),committed=m.getJSONArray("committed");Set<String> changed=new HashSet<>();for(int i=0;i<committed.length();i++)changed.add(committed.getString(i));
        // Preflight ALL restores, so a user edit prevents partial rollback.
        for(int i=0;i<rows.length();i++){
            JSONObject r=rows.getJSONObject(i);if(!changed.contains(r.getString("path")))continue;String rel=r.getString("path");Path p=root.resolve(rel).normalize();
            if(!p.startsWith(root)||!rel.matches("(?:system|system_ext|product|vendor|odm)/.*?/selinux/.+"))throw new IOException("非法回滚路径");canonical(p.getParent());
            Path bak=job.resolve("restore").resolve(rel);canonical(bak);if(!hash(bytes(bak)).equals(r.getString("before")))throw new IOException("备份已变化");
            stagedPath(root,r,"staging");stagedPath(root,r,"restore_staging");
            if(Files.exists(p,LinkOption.NOFOLLOW_LINKS)){canonical(p);String h=hash(bytes(p));if(!h.equals(r.getString("before"))&&(r.isNull("after")||!h.equals(r.getString("after"))))throw new IOException("有用户后续修改，拒绝覆盖: "+p);}
            else if(!r.isNull("after"))throw new IOException("文件被外部移除，停止回滚: "+p);
        }
        Engine runner=new Engine(job,tools,new JSONObject());
        for(int i=rows.length()-1;i>=0;i--){
            JSONObject r=rows.getJSONObject(i);String rel=r.getString("path");if(!changed.contains(rel))continue;
            // Only remove exact paths journaled by this transaction, never glob user files.
            for(String field:Arrays.asList("staging","restore_staging")){Path old=stagedPath(root,r,field);if(old!=null)Files.deleteIfExists(old);}
            Path p=root.resolve(rel),bak=job.resolve("restore").resolve(rel);String tmpRel=rel+".rpm-restore-"+UUID.randomUUID();
            r.put("restore_staging",tmpRel);m.put("status","restoring");json(job.resolve("transaction.json"),m);
            Path tmp=root.resolve(tmpRel);if(Files.exists(tmp,LinkOption.NOFOLLOW_LINKS))throw new IOException("恢复暂存路径已被占用: "+tmp);
            runner.run(Arrays.asList("/system/bin/cp","-a",bak.toString(),tmp.toString()),30,true);Files.move(tmp,p,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
            if(!hash(bytes(p)).equals(r.getString("before")))throw new IOException("回滚校验失败");
        }
        m.put("status","restored");json(job.resolve("transaction.json"),m);runner.run(Arrays.asList("/system/bin/sync"),30,true);System.out.println("恢复完成："+root);
    }
}
