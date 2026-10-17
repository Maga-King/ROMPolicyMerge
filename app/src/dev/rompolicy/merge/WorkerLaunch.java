package dev.rompolicy.merge;

/** Only the short-lived root worker gets a larger heap; never set global VM props. */
public final class WorkerLaunch {
    private WorkerLaunch(){}
    static String quote(String s){return "'"+s.replace("'","'\\''")+"'";}
    static int heapMiB(long totalBytes,long availableBytes){
        long budget=Math.min(totalBytes/4,availableBytes/2)/1048576;
        return (int)Math.max(256,Math.min(1536,budget/128*128));
    }
    static String command(String apk,String job,String tools,String mode,int heap){
        if(heap<256||heap>1536||!(mode.equals("merge")||mode.equals("restore")||mode.equals("probe")))throw new IllegalArgumentException("worker launch options");
        String options=" -Xmx"+heap+"m -XX:HeapGrowthLimit="+heap+"m";
        String entry=" dev.rompolicy.merge.RootWorker "+quote(job)+" "+quote(tools)+" "+quote(mode);
        // Android 9 system ART; Android 10 runtime APEX; Android 11+ ART APEX.
        return "echo '工作进程申请 Java 堆上限 "+heap+" MiB（按可用内存选取，不预先占满）'; "+
            "for rpm_vm in /apex/com.android.art/bin/dalvikvm64 /apex/com.android.runtime/bin/dalvikvm64 /system/bin/dalvikvm64; do "+
            "if [ -x \"$rpm_vm\" ]; then exec \"$rpm_vm\""+options+" -cp "+quote(apk)+entry+"; fi; done; "+
            "echo '未找到独立 ART，回退 app_process；该系统可能仍限制为 512 MiB，以实际日志为准'; "+
            "export CLASSPATH="+quote(apk)+"; exec /system/bin/app_process"+options+" /system/bin"+entry;
    }
}
