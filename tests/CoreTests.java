package dev.rompolicy.merge;
import java.util.*;
public class CoreTests {
 static int count;
 static void ok(boolean v,String name){if(!v)throw new AssertionError(name);count++;System.out.println("PASS "+name);}
 static Cil.Index idx(String s){Cil.Index i=new Cil.Index();for(Cil.N n:Cil.parse(s))i.add(n);return i;}
 static Cil.Merger merge(Cil.Index i,String s){Cil.Merger m=new Cil.Merger(i,(a,b,c,d)->{});m.targetVersion="202404";m.hardwareLabels=true;m.permissive=true;List<Cil.Entry> e=new ArrayList<>();for(Cil.N n:Cil.parse(s))e.add(new Cil.Entry("test","source",n));m.merge(e,"test");return m;}
 static String added(Cil.Merger m){StringBuilder b=new StringBuilder();for(Cil.Entry e:m.additions)if(e.active)b.append(e.node.text()).append('\n');return b.toString();}
 public static void main(String[] args)throws Exception{
  String base="(class file (read write open))(class process (transition ptrace))(type init)(type foo)(type bar)(typeattribute domain)(role r)(typeattributeset domain (init foo bar))";
  ok(Cil.parse("; (comment)\n(type a) (genfscon x \"/a; ()\" (u r t (s0 s0)))").size()==2,"parser comments and quoted parentheses");
  List<Cil.N> stream=new ArrayList<>();Cil.parse("(type foo)(allow foo foo (file (read)))",stream::add);
  ok(stream.size()==2&&stream.get(1).text().equals("(allow foo foo (file (read)))"),"incremental statement parser preserves text");
  ok(stream.get(0).a.get(1)==stream.get(1).a.get(1),"repeated atoms share storage within a parse");
  ok(WorkerLaunch.heapMiB(16L<<30,4L<<30)==1536&&WorkerLaunch.heapMiB(4L<<30,1L<<30)==512,"worker heap budget respects available memory and cap");
  ok(WorkerLaunch.command("/tmp/app's.apk","/tmp/job","/tmp/lib","probe",1536).contains("dalvikvm64"),"independent ART launcher and quoted paths");
  ok(Engine.devicePolicyFile("vendor_sepolicy.cil")&&Engine.devicePolicyFile("202404.compat.cil")&&Engine.devicePolicyFile("vendor_property_contexts")&&Engine.devicePolicyFile("plat_sepolicy_vers.txt"),"partition source includes CIL mappings contexts and interface version");
  ok(!Engine.devicePolicyFile("precompiled_sepolicy")&&!Engine.devicePolicyFile("precompiled_file_contexts")&&!Engine.devicePolicyFile("sepolicy.rule")&&!Engine.devicePolicyFile("running-policy.bin"),"partition source excludes binary caches and root module rule files");
  Engine route=new Engine(java.nio.file.Paths.get("/unused"),java.nio.file.Paths.get("/unused"),new org.json.JSONObject());route.version="202404";
  for(String part:Arrays.asList("system","system_ext","vendor"))route.dirs.put(part,part+"/etc/selinux");
  for(String name:Arrays.asList("system/etc/selinux/plat_sepolicy.cil","system/etc/selinux/mapping/202404.cil","system_ext/etc/selinux/system_ext_sepolicy.cil","vendor/etc/selinux/vendor_sepolicy.cil"))route.originals.put(name,new byte[0]);
  ok(route.variantDestination("system_ext",false).equals("system_ext/etc/selinux/system_ext_sepolicy.cil"),"normal additions retain partition ownership");
  route.originals.put("vendor/etc/selinux/vendor_sepolicy_debug.cil",new byte[0]);
  ok(route.variantDestination("system_ext",false).equals("vendor/etc/selinux/vendor_sepolicy.cil"),"normal-only additions never leak into shared debug inputs");
  ok(route.variantDestination("system_ext",true).equals("vendor/etc/selinux/vendor_sepolicy_debug.cil"),"debug-only additions never leak into a shared normal CIL");
  boolean fail=false;try{Cil.parse("(type a");}catch(Exception e){fail=true;}ok(fail,"unbalanced CIL rejected");
  Cil.Merger m=merge(idx(base+"(neverallow foo bar (file (write)))"),"(allow foo bar (file (read write)))(neverallow bar foo (file (read)))(allow init bar (process (ptrace)))");
  ok(added(m).contains("(read write)"),"neverallow does not trim allow");
  ok(added(m).contains("(ptrace)"),"broad init access not removed");
  ok(!added(m).contains("neverallow"),"source assertions excluded");
  Cil.Index originalAudit=idx(base+"(dontaudit foo bar (file (read)))");
  m=merge(originalAudit,"(dontaudit foo bar (file (write)))(dontauditx foo bar (ioctl file (0x12)))(auditallow foo bar (file (write)))");
  ok(!added(m).contains("dontaudit")&&added(m).contains("auditallow"),"source dontaudit and dontauditx excluded; auditallow retained");
  ok(originalAudit.exact.contains("(dontaudit foo bar (file (read)))"),"target original dontaudit preserved");
  m=merge(idx(base),"(allow new_type foo (file (read)))(type new_type)");ok(added(m).contains("allow new_type"),"forward type declarations");
  m=merge(idx(base+"(typeattribute group)"),"(typeattributeset group foo)");ok(added(m).contains("typeattributeset group (foo)"),"atomic attribute expression supported");
  ok(idx(base+"(typeattribute group)(typeattributeset group foo)").resolve("group").contains("foo"),"atomic target attributes resolved");
  m=merge(idx(base),"(expandtypeattribute (foo_202504) true)");ok(added(m).isEmpty(),"attribute expansion omitted only when remapped to concrete type");
  m=merge(idx(base),"(typeattribute foo_202504)(typeattributeset foo_202504 (foo))(allow foo_202504 bar (file (read)))");
  ok(added(m).contains("allow foo bar"),"version alias to concrete target type");ok(!added(m).contains("typeattributeset foo "),"no assigning attribute members to concrete type");
  m=merge(idx(base+"(typeattribute foo_202404)"),"(allow foo_202504 bar (file (read)))");ok(added(m).contains("foo_202404"),"target vendor version preferred");
  m=merge(idx(base),"(typeattribute foo_33_0)(typeattributeset foo_33_0 (foo))(allow foo_33_0 bar (file (read)))");ok(added(m).contains("allow foo bar"),"legacy SDK version alias");
  m=merge(idx(base+"(typeattribute system_property_type)(typeattribute vendor_property_type)(typeattributeset system_property_type (foo))"),"(type new_prop)(typeattributeset vendor_property_type (foo new_prop))");
  ok(added(m).contains("vendor_property_type (new_prop)"),"target property ownership protected; new type retained");
  m=merge(idx(base),"(typepermissive init)(typepermissive foo)");ok(added(m).contains("typepermissive foo")&&!added(m).contains("typepermissive init"),"explicit early-init permissive exception");
  m=merge(idx(base+"(typetransition foo bar process foo)"),"(typetransition foo bar process bar)(allow foo bar (process (transition)))");ok(!added(m).contains("typetransition")&&added(m).contains("allow"),"transition conflict does not trim allows");
  List<Cil.N> extra=new ExtraRules(idx(base)).parse("neverallow unknown unknown:absent impossible; neverallowxperm unknown unknown:absent ioctl *; allow foo bar:file { read write };","te");
  ok(extra.size()==1&&extra.get(0).head().equals("allow"),"TE assertions ignored without resolving source-only symbols");
  extra=new ExtraRules(idx(base)).parse("dontaudit missing absent:unknown whatever; dontauditxperm missing absent:unknown ioctl *; allow foo bar:file read;","te");
  ok(extra.size()==1&&extra.get(0).head().equals("allow"),"extra TE dontaudit exclusions do not fail the merge");
  extra=new ExtraRules(idx(base)).parse("allow foo bar file *\nallowxperm foo bar file ioctl 0x0010-0x0020","magisk");ok(extra.size()==2&&extra.get(1).head().equals("allowx"),"Magisk wildcard and xperm");
  Cil.Index bi=idx(base+"(class binder (call transfer impersonate set_context_mgr))");
  Set<String> beforeExtra=new HashSet<>(bi.exact);Set<String> beforeSymbols=new HashSet<>(bi.symbols.keySet());
  extra=new ExtraRules(bi).parse("allow foo bar binder { ioctl call }\nallow foo bar missing_class read\nallowxperm foo bar binder ioctl 0x10","magisk");
  ok(bi.exact.equals(beforeExtra)&&bi.symbols.keySet().equals(beforeSymbols),"extra parser never mutates merger index");
  List<Cil.N> sets=new ExtraRules(bi).parse("attribute rpm_extra_set_0\nallow { foo bar } foo file read\nallow { foo bar } bar file write","magisk");
  Set<String> generated=new HashSet<>();for(Cil.N n:sets)if(n.head().equals("typeattribute"))generated.add(n.s(1));
  ok(generated.size()==3&&generated.contains("rpm_extra_set_2"),"extra selector names do not collide with own declarations");
  StringBuilder converted=new StringBuilder();for(Cil.N n:extra)converted.append(n.text());
  m=merge(idx(base+"(class binder (call transfer impersonate set_context_mgr))"),converted.toString());
  ok(added(m).contains("(allow foo bar (binder (call)))")&&!added(m).contains("ioctl"),"invalid binder ioctl removed, valid call preserved");
  ok(!added(m).contains("missing_class"),"unknown extra class uses same screening as ROM rules");
  fail=false;try{new ExtraRules(idx(base)).parse("some_m4(foo)","te");}catch(Exception e){fail=true;}ok(fail,"unsupported extras stop rather than silently succeed");
  ok(Engine.kind("tee_service_contexts").equals("tee_service_contexts"),"TEE context namespace separated");
  ok(Engine.contextKey("persist.test u:object_r:foo:s0","property_contexts").equals(Engine.contextKey("persist.test u:object_r:foo:s0 prefix","property_contexts")),"implicit and explicit prefix collide");
  ok(!Engine.contextKey("persist.test u:object_r:foo:s0 exact","property_contexts").equals(Engine.contextKey("persist.test u:object_r:foo:s0 prefix","property_contexts")),"exact and prefix remain distinct");
  ok(Engine.lines("foo bar # comment\n# whole\n".getBytes()).equals(Collections.singletonList("foo bar")),"inline context comments ignored");
  Map<String,String> cd=new LinkedHashMap<>();for(String p:Arrays.asList("system","system_ext","product","vendor","odm"))cd.put(p,p+"/etc/selinux");
  Map<String,byte[]> cf=new LinkedHashMap<>();List<String> ca=new ArrayList<>();
  String vf="vendor/etc/selinux/vendor_file_contexts",of="odm/etc/selinux/odm_file_contexts",sf="system_ext/etc/selinux/system_ext_file_contexts",cache="odm/etc/selinux/precompiled_file_contexts";
  cf.put(vf,"# keep\r\n/data/fp(/.*)? u:object_r:foo:s0\r\n/data/other u:object_r:foo:s0\r\n/data/fp(/.*)? -d u:object_r:foo:s0\r\n".getBytes());
  cf.put(of,"/data/fp(/.*)? u:object_r:foo:s0\n".getBytes());cf.put(sf,"/data/fp(/.*)? u:object_r:bar:s0\n".getBytes());
  cf.put(cache,"/data/fp(/.*)? u:object_r:foo:s0\n".getBytes());
  ContextPriority.resolve(cf,cd,(a,b,c,d)->ca.add(a));
  ok(Engine.text(cf.get(vf)).equals("# keep\r\n/data/other u:object_r:foo:s0\r\n/data/fp(/.*)? -d u:object_r:foo:s0\r\n"),"platform wins exact file key without changing unrelated lines or CRLF");
  ok(cf.get(of).length==0&&Engine.text(cf.get(cache)).contains("bar:s0"),"ODM conflict removed and precompiled text cache synchronized");
  ok(ca.size()==3&&ca.contains("CONTEXT_CACHE_RESOLVED"),"all context resolutions audited");
  int notesBefore=ca.size();ContextPriority.resolve(cf,cd,(a,b,c,d)->ca.add(a));ok(ca.size()==notesBefore,"context precedence idempotent");
  cf.put("system/etc/selinux/plat_property_contexts","persist.test u:object_r:bar:s0 exact string\n".getBytes());
  cf.put("vendor/etc/selinux/vendor_property_contexts","persist.test u:object_r:foo:s0 prefix string\npersist.test u:object_r:foo:s0 exact string\n".getBytes());
  ContextPriority.resolve(cf,cd,(a,b,c,d)->{});
  ok(Engine.text(cf.get("vendor/etc/selinux/vendor_property_contexts")).equals("persist.test u:object_r:foo:s0 prefix string\n"),"property priority preserves distinct prefix vs exact selectors");
  cf.put(vf,"/data/fp(/.*)? u:object_r:foo:s0\n".getBytes());cf.put("product/etc/selinux/product_file_contexts","/data/fp(/.*)? u:object_r:baz:s0\n".getBytes());
  fail=false;try{ContextPriority.resolve(cf,cd,(a,b,c,d)->{});}catch(java.io.IOException ex){fail=true;}ok(fail,"ambiguous platform labels refuse automatic device-side resolution");
  java.nio.file.Path scratch=java.nio.file.Files.createTempFile(java.nio.file.Paths.get("/data/local/tmp"),"rpm-log-test-",".txt");
  byte[] message="中文实时日志\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  java.nio.file.Files.write(scratch,Arrays.copyOf(message,2));RuntimeLog.Tailer tailer=new RuntimeLog.Tailer(scratch);
  ok(tailer.poll(false).isEmpty(),"partial UTF-8 line buffered until complete");
  java.nio.file.Files.write(scratch,Arrays.copyOfRange(message,2,message.length),java.nio.file.StandardOpenOption.APPEND);
  ok(tailer.poll(false).equals(Collections.singletonList("中文实时日志")),"live log handles split Chinese UTF-8 bytes");
  ok(tailer.poll(false).isEmpty(),"live log does not repeat old output");
  ok(RuntimeLog.translate("Building policy binary").startsWith("编译阶段"),"compiler progress translated to Chinese");
  if(args.length==2){
   Cil.Index real=idx(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(args[0])),java.nio.charset.StandardCharsets.UTF_8));
   List<Cil.N> parsed=new ExtraRules(real).parse(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(args[1])),java.nio.charset.StandardCharsets.UTF_8),"auto");
   ok(parsed.size()>0,"actual failing extra.rule now parses completely ("+parsed.size()+" statements)");
  }
  if(args.length==1){
   Process child=new ProcessBuilder("/system/bin/sh","-c",WorkerLaunch.command(args[0],"unused","unused","probe",1536)).redirectErrorStream(true).start();
   java.io.ByteArrayOutputStream output=new java.io.ByteArrayOutputStream();byte[] chunk=new byte[4096];int got;while((got=child.getInputStream().read(chunk))!=-1)output.write(chunk,0,got);
   String report=output.toString("UTF-8");System.out.println(report);
   ok(child.waitFor()==0&&report.contains("工作进程堆上限 1536 MiB"),"actual APK launcher obtains 1536 MiB without device property changes");
  }
  System.out.println("CORE_TESTS_PASS="+count);
 }
}
