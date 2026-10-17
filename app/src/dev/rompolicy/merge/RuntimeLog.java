package dev.rompolicy.merge;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Bounded live reads, independent of Android UI and without reading the whole log on every tick. */
public final class RuntimeLog {
    public static String tail(Path file,int limit)throws IOException{
        if(!Files.exists(file))return "";
        try(RandomAccessFile f=new RandomAccessFile(file.toFile(),"r")){
            long length=f.length(),start=Math.max(0,length-limit);f.seek(start);byte[] data=new byte[(int)(length-start)];f.readFully(data);
            int skip=0;if(start>0)while(skip<data.length&&(data[skip]&0xc0)==0x80)skip++;
            return (start>0?"（窗口仅显示日志末尾，完整内容可用“保存日志”导出）\n":"")+new String(data,skip,data.length-skip,StandardCharsets.UTF_8);
        }
    }
    public static final class Tailer {
        private final Path file;private long position;private final ByteArrayOutputStream pending=new ByteArrayOutputStream();
        public Tailer(Path p){file=p;}
        public List<String> poll(boolean eof)throws IOException{
            List<String> lines=new ArrayList<>();if(!Files.exists(file))return lines;
            try(RandomAccessFile f=new RandomAccessFile(file.toFile(),"r")){
                if(f.length()<position){position=0;pending.reset();}
                f.seek(position);byte[] data=new byte[8192];int budget=1024*1024,n;
                while(budget>0&&(n=f.read(data,0,Math.min(data.length,budget)))>0){position+=n;budget-=n;
                    for(int i=0;i<n;i++){if(data[i]=='\n'){emit(lines);}else if(pending.size()<16384)pending.write(data[i]);}
                }
            }
            if(eof&&pending.size()>0)emit(lines);return lines;
        }
        private void emit(List<String> lines){String s=new String(pending.toByteArray(),StandardCharsets.UTF_8).trim();pending.reset();if(!s.isEmpty())lines.add(s);}
    }
    public static String translate(String line){
        if(line.startsWith("Parsing "))return "编译器正在读取："+line.substring(8);
        if(line.equals("Building AST from Parse Tree"))return "编译阶段：构建 CIL 语法树";
        if(line.equals("Destroying Parse Tree"))return "编译阶段：释放已完成解析的临时数据";
        if(line.equals("Resolving AST"))return "编译阶段：解析类型、属性和规则引用";
        if(line.equals("Qualifying Names"))return "编译阶段：处理名称和命名空间";
        if(line.equals("Compile post process"))return "编译阶段：处理属性展开和一致性检查";
        if(line.equals("Building policy binary"))return "编译阶段：生成策略二进制（大型策略可能需要数分钟）";
        if(line.startsWith("readback_ok policy_version="))return "二进制读取通过，策略版本 "+line.substring(line.indexOf('=')+1);
        if(line.startsWith("roundtrip_ok policy_version="))return "二进制写出再回读通过，策略版本 "+line.substring(line.indexOf('=')+1);
        if(line.startsWith("contexts="))return "标签校验统计："+line.replace("contexts=","标签数量=").replace("invalid=","无效数量=");
        if(line.startsWith("INVALID_CONTEXT "))return "发现无效 SELinux 标签："+line.substring(16);
        if(line.contains("Conflicting type rules"))return "编译器发现类型转换冲突："+line;
        if(line.contains("Failed to"))return "编译器报告失败："+line;
        return "校验输出："+line;
    }
}
