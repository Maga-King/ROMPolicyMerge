package dev.rompolicy.merge;
import android.system.Os;
import java.nio.file.*;
import java.nio.channels.*;
import org.json.*;

public final class RootWorker {
    public static void main(String[] args){
        Path job=null;
        try{
            if(Os.getuid()!=0)throw new IllegalStateException("没有获得 root 授权");
            // app_process inherits dalvik.vm.heapgrowthlimit even with -Xmx on some ROMs.
            // Lift this process's soft growth cap only; no device property is changed.
            try{Class<?> vm=Class.forName("dalvik.system.VMRuntime");Object runtime=vm.getMethod("getRuntime").invoke(null);vm.getMethod("clearGrowthLimit").invoke(runtime);}catch(ReflectiveOperationException unsupported){System.out.println("无法调整工作进程的内存增长上限，使用当前限制");}
            System.out.println("工作进程堆上限 "+Runtime.getRuntime().maxMemory()/1048576+" MiB");
            if(args.length!=3)throw new IllegalArgumentException("worker arguments");
            if(args[2].equals("probe")){System.out.println("独立工作进程启动正常，仅探测内存，未读取或修改 ROM");return;}
            if(Runtime.getRuntime().maxMemory()<=512L*1048576)System.out.println("注意：当前工作进程仍受小堆限制；大型多来源策略建议释放内存后再试");
            job=Paths.get(args[0]);Engine.canonical(job);Path tools=Paths.get(args[1]);Engine.canonical(tools);
            Path lockPath=Paths.get("/data/local/tmp/rompolicymerge-worker.lock");if(Files.exists(lockPath))Engine.canonical(lockPath);
            try(FileChannel channel=FileChannel.open(lockPath,StandardOpenOption.CREATE,StandardOpenOption.WRITE);FileLock lock=channel.tryLock()){
                if(lock==null)throw new IllegalStateException("另一个合并任务正在进行，不能并发修改");
                if(args[2].equals("restore"))Engine.restore(job,tools);
                else if(args[2].equals("merge"))new Engine(job,tools,new JSONObject(Engine.text(job.resolve("request.json")))).execute();
                else throw new IllegalArgumentException("unknown mode");
                String message="恢复完成";
                if(args[2].equals("merge")){
                    JSONObject summary=new JSONObject(Engine.text(job.resolve("summary.json")));
                    JSONObject counts=summary.optJSONObject("counts");
                    message=summary.optBoolean("validate_only")?"仅验证通过，未写回":"合并验证通过，已按需写回";
                    if(counts!=null)message+="；跳过 "+counts.optInt("SKIPPED")+" 项，权限筛选 "+counts.optInt("FILTERED")+" 项，转换冲突 "+counts.optInt("COMPILER_CONFLICT")+" 项。详情见报告";
                }
                Engine.json(job.resolve("result.json"),new JSONObject().put("success",true).put("mode",args[2]).put("message",message));
            }
        }catch(Throwable t){
            t.printStackTrace(System.out);
            if(job!=null)try{Engine.json(job.resolve("result.json"),new JSONObject().put("success",false).put("message",String.valueOf(t.getMessage())).put("warning","若在写回阶段失败，请检查 transaction.json 的状态，必要时点恢复备份。"));}catch(Exception ignored){}
            System.exit(1);
        }
    }
}
