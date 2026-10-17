package dev.rompolicy.merge;
import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.os.*;
import java.io.*;
import java.nio.file.*;
import org.json.*;

public final class MergeService extends Service {
    public static volatile boolean running=false;
    public android.os.IBinder onBind(Intent i){return null;}
    static String quote(String s){return "'"+s.replace("'","'\\''")+"'";}
    @Override public int onStartCommand(Intent intent,int flags,int id){
        if(intent==null){stopSelf();return START_NOT_STICKY;}if(running)return START_NOT_STICKY;
        running=true;
        NotificationManager nm=getSystemService(NotificationManager.class);nm.createNotificationChannel(new NotificationChannel("merge","规则合并任务",NotificationManager.IMPORTANCE_LOW));
        PendingIntent pi=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        Notification note=new Notification.Builder(this,"merge").setSmallIcon(android.R.drawable.stat_sys_upload).setContentTitle("正在处理 ROM 策略").setContentText("保持手机开机，勿同时修改目标解包目录").setContentIntent(pi).setOngoing(true).build();
        if(Build.VERSION.SDK_INT>=34)startForeground(1,note,ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);else startForeground(1,note);
        String path=intent.getStringExtra("job"),mode=intent.getStringExtra("mode");
        new Thread(()->{
            PowerManager.WakeLock wake=getSystemService(PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"ROMPolicyMerge:compile");wake.acquire(40*60*1000L);
            Path job=Paths.get(path);
            try{
                String apk=getApplicationInfo().sourceDir,tools=getApplicationInfo().nativeLibraryDir;
                ActivityManager.MemoryInfo memory=new ActivityManager.MemoryInfo();getSystemService(ActivityManager.class).getMemoryInfo(memory);
                String cmd=WorkerLaunch.command(apk,path,tools,mode,WorkerLaunch.heapMiB(memory.totalMem,memory.availMem));
                Path log=job.resolve(mode.equals("restore")?"restore-console.txt":"console.txt");
                java.lang.Process p=new ProcessBuilder("su","-c",cmd).redirectErrorStream(true).redirectOutput(log.toFile()).start();
                int status=p.waitFor();
                if(!Files.exists(job.resolve("result.json")))Engine.json(job.resolve("result.json"),new JSONObject().put("success",false).put("message","root worker 未完成，退出码 "+status+"。检查 root 授权和日志。"));
            }catch(Exception e){try{Engine.json(job.resolve("result.json"),new JSONObject().put("success",false).put("message",e.toString()));}catch(Exception ignored){}}
            finally{if(wake.isHeld())wake.release();running=false;stopForeground(STOP_FOREGROUND_REMOVE);stopSelf();}
        },"ROM-merge").start();return START_NOT_STICKY;
    }
}
