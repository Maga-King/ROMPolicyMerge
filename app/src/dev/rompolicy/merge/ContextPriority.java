package dev.rompolicy.merge;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Exact-key precedence only; never guesses whether two different regexes overlap. */
final class ContextPriority {
    static boolean platform(String path,Map<String,String> dirs){
        if(path==null)return false;
        for(String p:Arrays.asList("system","system_ext","product"))
            if(dirs.containsKey(p)&&path.startsWith(dirs.get(p)+"/"))return true;
        return false;
    }
    static boolean device(String path,Map<String,String> dirs){
        if(path==null)return false;
        for(String p:Arrays.asList("vendor","odm"))
            if(dirs.containsKey(p)&&path.startsWith(dirs.get(p)+"/"))return true;
        return false;
    }
    static String normalized(String s){return s.trim().replaceAll("\\s+"," ");}
    static void resolve(Map<String,byte[]> files,Map<String,String> dirs,Cil.Audit audit)throws IOException{
        Map<String,String> winners=new HashMap<>(),owners=new HashMap<>();
        Set<String> ambiguous=new HashSet<>();
        for(Map.Entry<String,byte[]> e:files.entrySet()){
            String kind=Engine.kind(e.getKey());
            if(kind==null||e.getKey().contains("/precompiled_")||!platform(e.getKey(),dirs))continue;
            for(String line:Engine.lines(e.getValue())){
                if(line.startsWith("neverallow"))continue;
                String key=kind+"\n"+Engine.contextKey(line,kind),old=winners.putIfAbsent(key,line);
                owners.putIfAbsent(key,e.getKey());
                if(old!=null&&!normalized(old).equals(normalized(line)))ambiguous.add(key);
            }
        }
        for(Map.Entry<String,byte[]> e:files.entrySet()){
            String kind=Engine.kind(e.getKey());if(kind==null||!device(e.getKey(),dirs))continue;
            boolean cache=e.getKey().contains("/precompiled_"),changed=false;
            String original=Engine.text(e.getValue());
            if(original.indexOf('\0')>=0)throw new IOException("不支持二进制 contexts，未写回: "+e.getKey());
            StringBuilder out=new StringBuilder();
            for(String raw:original.split("(?<=\n)",-1)){
                List<String> parsed=Engine.lines(raw.getBytes(StandardCharsets.UTF_8));
                String line=parsed.isEmpty()?"":parsed.get(0);
                String key=kind+"\n"+(line.isEmpty()?"":Engine.contextKey(line,kind));
                String keep=line.startsWith("neverallow")?null:winners.get(key);
                if(keep!=null&&!normalized(keep).equals(normalized(line))){
                    if(ambiguous.contains(key)){
                        audit.note("CONTEXT_PRIORITY_AMBIGUOUS",e.getKey(),null,"平台侧也有冲突，无法自动选择: "+line);
                        throw new IOException("system/system_ext/product 内部同键冲突，未自动裁决: "+line);
                    }
                    audit.note(cache?"CONTEXT_CACHE_RESOLVED":"CONTEXT_PRIORITY_REMOVED",e.getKey(),null,
                        line+" -> 保留 "+owners.get(key)+": "+keep);
                    // A merged cache still needs this key, but must use the platform label.
                    if(cache)out.append(keep).append(raw.endsWith("\r\n")?"\r\n":raw.endsWith("\n")?"\n":"");
                    changed=true;
                }else out.append(raw);
            }
            if(changed)e.setValue(out.toString().getBytes(StandardCharsets.UTF_8));
        }
    }
}
