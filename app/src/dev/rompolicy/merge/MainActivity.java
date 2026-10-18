package dev.rompolicy.merge;
import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.os.*;
import android.view.*;
import android.widget.*;
import android.net.Uri;
import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import org.json.*;

public final class MainActivity extends Activity {
    EditText target,source;TextView extraLabel,status,output;CheckBox live,permissive,otaOnly,repairDebug,validateOnly;Spinner format,policyVersion;
    Button start,restore;Path extra,lastJob;final Handler handler=new Handler();boolean active=true;long launchingUntil=0;
    ScrollView logBox;CheckBox followLog;String displayedLog="";
    final class LogScroll extends ScrollView {
        LogScroll(){super(MainActivity.this);}
        @Override public boolean dispatchTouchEvent(android.view.MotionEvent e){
            int a=e.getActionMasked();
            if(a==android.view.MotionEvent.ACTION_DOWN){getParent().requestDisallowInterceptTouchEvent(true);followLog.setChecked(false);}
            else if(a==android.view.MotionEvent.ACTION_MOVE)getParent().requestDisallowInterceptTouchEvent(true);
            else if(a==android.view.MotionEvent.ACTION_UP||a==android.view.MotionEvent.ACTION_CANCEL)getParent().requestDisallowInterceptTouchEvent(false);
            return super.dispatchTouchEvent(e);
        }
    }
    int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    TextView label(LinearLayout box,String s,int size){TextView v=new TextView(this);v.setText(s);v.setTextSize(size);v.setTextColor(Color.rgb(28,38,52));v.setPadding(0,dp(8),0,dp(8));box.addView(v);return v;}
    Button button(LinearLayout box,String s,Runnable r){Button b=new Button(this);b.setText(s);b.setAllCaps(false);box.addView(b,new LinearLayout.LayoutParams(-1,dp(52)));b.setOnClickListener(v->r.run());return b;}
    EditText path(LinearLayout box,String hint){EditText v=new EditText(this);v.setSingleLine(true);v.setHint(hint);v.setTextSize(15);v.setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);box.addView(v,new LinearLayout.LayoutParams(-1,dp(52)));return v;}
    @Override public void onCreate(Bundle b){super.onCreate(b);
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);LinearLayout page=new LinearLayout(this);page.setOrientation(1);page.setPadding(dp(22),dp(24),dp(22),dp(24));page.setBackgroundColor(Color.rgb(246,248,252));scroll.addView(page);setContentView(scroll);
        page.setOnApplyWindowInsetsListener((v,insets)->{v.setPadding(dp(22),dp(12)+insets.getSystemWindowInsetTop(),dp(22),dp(24)+insets.getSystemWindowInsetBottom());return insets;});
        label(page,"ROM 规则合并",27);label(page,"ROOT · 离线处理 · 先备份再写回",13);
        label(page,"需要补规则的 ROM 解包路径",17);target=path(page,"/data/DNA/DNA_AA");
        label(page,"补充规则的来源 ROM（只读）",17);source=path(page,"/data/DNA/DNA_BB");
        label(page,"只处理 system / system_ext / product / vendor / odm 的 SELinux。路径必须是真实解包目录，不能选择正在运行的系统分区。",13);
        otaOnly=new CheckBox(this);otaOnly.setText("OTA 模式：只写 vendor / odm，平台分区只读验证");page.addView(otaOnly);
        label(page,"目标须包含完整平台策略。来源可以仅有 vendor/odm；不会借用当前手机或伪造来源 system。",12);
        live=new CheckBox(this);live.setText("同时将当前手机五分区的 SELinux 文件作为来源");page.addView(live);
        label(page,"读取分区 CIL、mapping 和 contexts，不导出内核策略，不收集 KSU/Magisk 动态注入的规则。若分区文件本身被模块覆盖，读到的是覆盖后的可见文件。",12);
        LinearLayout advanced=new LinearLayout(this);advanced.setOrientation(1);advanced.setVisibility(View.GONE);
        button(page,"可选高级设置 ▾",()->advanced.setVisibility(advanced.getVisibility()==View.VISIBLE?View.GONE:View.VISIBLE));page.addView(advanced);
        extraLabel=label(advanced,"未选择额外规则",14);
        button(advanced,"选择 sepolicy.rule / TE 文件",()->{Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.setType("*/*");i.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(i,10);});
        button(advanced,"清除额外规则",()->{extra=null;extraLabel.setText("未选择额外规则");});
        repairDebug=new CheckBox(this);repairDebug.setText("向 debug 补齐普通 vendor/odm 规则（含目标已有补丁）");repairDebug.setChecked(true);advanced.addView(repairDebug);
        validateOnly=new CheckBox(this);validateOnly.setText("只生成候选并验证，不写回目标");advanced.addView(validateOnly);
        format=new Spinner(this);format.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,new String[]{"自动识别格式","Magisk sepolicy.rule","TE 基础语法（不执行 m4 宏）"}));advanced.addView(format);
        label(advanced,"编译二进制版本（不是 Android 版本或 202404 这类接口版本）",13);
        policyVersion=new Spinner(this);policyVersion.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,new String[]{"自动：优先目标预编译策略，否则 33","33","32","31","30","29","28","27","26"}));advanced.addView(policyVersion);
        permissive=new CheckBox(this);permissive.setText("吸收来源的域宽容（不新增 init / vendor_init / ueventd 宽容）");permissive.setChecked(true);advanced.addView(permissive);
        label(advanced,"所有来源的 neverallow / neverallowx、dontaudit / dontauditx 都不导入。目标原规则保留，验证使用 -N，不因 neverallow 或权限大裁 allow。文件标签、属性标签和 genfscon 会尝试合并；同键 contexts 冲突优先保留平台标签，同侧保留目标并记录。跨硬件标签也可能影响运行。",13);
        label(page,"点击后自动备份 → 合并 → 完整编译/回读/标签检查 → 写回目标。验证失败不写回。离线通过不保证开机，不能替代真机验证。",14);
        start=button(page,"开始修改",this::begin);start.setTextColor(Color.WHITE);start.setBackgroundTintList(android.content.res.ColorStateList.valueOf(Color.rgb(40,81,208)));
        restore=button(page,"恢复上次备份",this::restore);button(page,"保存日志",()->{if(lastJob==null){toast("还没有任务日志");return;}Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);i.setType("text/plain");i.addCategory(Intent.CATEGORY_OPENABLE);i.putExtra(Intent.EXTRA_TITLE,"ROM规则合并日志-"+lastJob.getFileName()+".txt");startActivityForResult(i,20);});
        status=label(page,"尚未开始",16);label(page,"实时日志 · 框内上下滑动查看",14);
        LinearLayout controls=new LinearLayout(this);controls.setOrientation(0);page.addView(controls);
        followLog=new CheckBox(this);followLog.setText("跟随最新日志");followLog.setChecked(true);controls.addView(followLog,new LinearLayout.LayoutParams(0,dp(48),1));
        Button latest=new Button(this);latest.setText("回到最新");controls.addView(latest,new LinearLayout.LayoutParams(dp(104),dp(48)));
        logBox=new LogScroll();logBox.setFillViewport(true);logBox.setVerticalScrollBarEnabled(true);logBox.setScrollbarFadingEnabled(false);
        android.graphics.drawable.GradientDrawable border=new android.graphics.drawable.GradientDrawable();border.setColor(Color.WHITE);border.setCornerRadius(dp(8));border.setStroke(dp(1),Color.rgb(205,214,226));logBox.setBackground(border);
        page.addView(logBox,new LinearLayout.LayoutParams(-1,dp(280)));
        output=new TextView(this);output.setTextSize(12);output.setTextColor(Color.rgb(28,38,52));output.setPadding(dp(12),dp(10),dp(12),dp(10));output.setTextIsSelectable(true);logBox.addView(output,new ScrollView.LayoutParams(-1,-2));
        output.setText("日志会实时显示在这里。工具不会刷镜像、重启、修改 boot 或注入当前内核策略。");
        latest.setOnClickListener(v->{followLog.setChecked(true);logBox.post(()->logBox.fullScroll(View.FOCUS_DOWN));});
        followLog.setOnCheckedChangeListener((v,checked)->{if(checked)logBox.post(()->logBox.fullScroll(View.FOCUS_DOWN));});
        android.content.SharedPreferences p=getSharedPreferences("ui",0);target.setText(p.getString("target",""));source.setText(p.getString("source",""));otaOnly.setChecked(p.getBoolean("otaOnly",false));repairDebug.setChecked(p.getBoolean("repairDebug",true));String old=p.getString("lastJob","");if(!old.isEmpty())lastJob=Paths.get(old);
        handler.post(poll);
    }
    void toast(String s){Toast.makeText(this,s,Toast.LENGTH_LONG).show();}
    void begin(){
        if(MergeService.running||SystemClock.elapsedRealtime()<launchingUntil)return;if(target.getText().toString().trim().isEmpty()||source.getText().toString().trim().isEmpty()){toast("先填写两个 ROM 解包路径");return;}
        try{
            String name=new SimpleDateFormat("yyyyMMdd-HHmmss",Locale.ROOT).format(new Date())+"-"+UUID.randomUUID().toString().substring(0,6);
            lastJob=getFilesDir().getCanonicalFile().toPath().resolve("jobs").resolve(name);Files.createDirectories(lastJob);
            JSONObject r=new JSONObject().put("target",target.getText().toString().trim()).put("source",source.getText().toString().trim()).put("live",live.isChecked()).put("permissive",permissive.isChecked()).put("hardware",true).put("format",new String[]{"auto","magisk","te"}[format.getSelectedItemPosition()]);
            r.put("write_scope",otaOnly.isChecked()?"vendor_odm":"all").put("repair_debug",repairDebug.isChecked()).put("validate_only",validateOnly.isChecked());
            if(policyVersion.getSelectedItemPosition()>0)r.put("policy_version",String.valueOf(34-policyVersion.getSelectedItemPosition()));
            if(extra!=null){Path copy=lastJob.resolve("extra.rule");Files.copy(extra,copy);r.put("extra",copy.toString());}
            Engine.json(lastJob.resolve("request.json"),r);getSharedPreferences("ui",0).edit().putString("target",r.getString("target")).putString("source",r.getString("source")).putBoolean("otaOnly",otaOnly.isChecked()).putBoolean("repairDebug",repairDebug.isChecked()).putString("lastJob",lastJob.toString()).apply();launch("merge");
        }catch(Exception e){toast(e.toString());}
    }
    void launch(String mode){
        launchingUntil=SystemClock.elapsedRealtime()+2500;start.setEnabled(false);restore.setEnabled(false);
        if(Build.VERSION.SDK_INT>=33&&checkSelfPermission("android.permission.POST_NOTIFICATIONS")!=android.content.pm.PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"},50);
        Intent i=new Intent(this,MergeService.class).putExtra("job",lastJob.toString()).putExtra("mode",mode);startForegroundService(i);status.setText("正在请求 root 并准备任务…");
    }
    void restore(){
        if(MergeService.running)return;
        if(lastJob==null||!Files.exists(lastJob.resolve("transaction.json"))){String previous=getSharedPreferences("ui",0).getString("lastBackupJob","");if(!previous.isEmpty())lastJob=Paths.get(previous);}
        if(lastJob==null||!Files.exists(lastJob.resolve("transaction.json"))){toast("没有可恢复的写回记录");return;}
        new AlertDialog.Builder(this).setTitle("恢复上次备份？").setMessage("只恢复该次任务修改的规则及移出的缓存。如果文件后来被别的工具修改，会拒绝覆盖。").setNegativeButton("取消",null).setPositiveButton("恢复",(d,w)->{try{Files.deleteIfExists(lastJob.resolve("result.json"));launch("restore");}catch(Exception e){toast(e.toString());}}).show();
    }
    final Runnable poll=new Runnable(){public void run(){if(!active)return;boolean busy=MergeService.running||SystemClock.elapsedRealtime()<launchingUntil;start.setEnabled(!busy);restore.setEnabled(!busy);
        if(lastJob!=null)try{
            Path log=lastJob.resolve("console.txt");String s=Files.exists(log)?RuntimeLog.tail(log,65536):"正在准备…";
            Path rr=lastJob.resolve("restore-console.txt");if(Files.exists(rr))s+="\n恢复记录\n"+RuntimeLog.tail(rr,32768);
            if(!s.equals(displayedLog)){int y=logBox.getScrollY();displayedLog=s;output.setText(s);if(followLog.isChecked())logBox.post(()->logBox.fullScroll(View.FOCUS_DOWN));else logBox.post(()->logBox.scrollTo(0,y));}
            if(Files.exists(lastJob.resolve("transaction.json"))&&!lastJob.toString().equals(getSharedPreferences("ui",0).getString("lastBackupJob","")))getSharedPreferences("ui",0).edit().putString("lastBackupJob",lastJob.toString()).apply();
            Path result=lastJob.resolve("result.json");if(Files.exists(result)){JSONObject j=new JSONObject(Engine.text(result));status.setText((j.optBoolean("success")?"完成：":"未完成：")+j.optString("message"));}
            else if(MergeService.running)status.setText("正在处理，请勿同时修改目标目录…");
            else if(Files.exists(lastJob.resolve("transaction.json")))status.setText("有上次任务记录；若处理中断，可查看日志并恢复备份");
        }catch(Exception ignored){}handler.postDelayed(this,1000);}};
    @Override protected void onDestroy(){active=false;handler.removeCallbacks(poll);super.onDestroy();}
    @Override protected void onActivityResult(int req,int result,Intent data){super.onActivityResult(req,result,data);if(result!=RESULT_OK||data==null||data.getData()==null)return;
        Uri uri=data.getData();new Thread(()->{try{
            if(req==10){Path p=getFilesDir().toPath().resolve("selected-"+UUID.randomUUID()+".rule");try(InputStream in=getContentResolver().openInputStream(uri);OutputStream out=Files.newOutputStream(p)){byte[] b=new byte[16384];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>16*1024*1024)throw new IOException("额外规则超过16MB");out.write(b,0,n);}}extra=p;runOnUiThread(()->extraLabel.setText("已选择额外规则文件（复制到私有目录）"));}
            else if(req==20){try(OutputStream stream=getContentResolver().openOutputStream(uri);Writer w=new OutputStreamWriter(stream,java.nio.charset.StandardCharsets.UTF_8)){
                w.write("ROM规则合并 1.0.5\n任务目录 "+lastJob+"\n\n");for(String n:Arrays.asList("request.json","result.json","summary.json","validation.json","discovery.json","contexts-invalid-normal.json","contexts-invalid-debug.json","console.txt","restore-console.txt","transaction.json")){Path p=lastJob.resolve(n);if(Files.exists(p)){w.write("\n"+n+"\n");w.write(Engine.text(p));}}
                w.write("\ncontexts 冲突和新增记录\n");Path audit=lastJob.resolve("audit.jsonl");if(Files.exists(audit))try(BufferedReader br=Files.newBufferedReader(audit)){String l;while((l=br.readLine())!=null){try{JSONObject r=new JSONObject(l);if(r.optString("status").startsWith("CONTEXT"))w.write(l+"\n");}catch(JSONException incomplete){w.write("当前任务仍在写日志，本次保存未包含末尾未完成记录。\n");}}}
                w.write("\n跳过/筛选/冲突详情\n");if(Files.exists(audit))try(BufferedReader br=Files.newBufferedReader(audit)){String l;while((l=br.readLine())!=null){try{JSONObject r=new JSONObject(l);if(Arrays.asList("SKIPPED","FILTERED","COMPILER_CONFLICT").contains(r.optString("status")))w.write(l+"\n");}catch(JSONException incomplete){break;}}}
                w.write("\n逐条 CIL 审计和编译器原始日志保留在任务目录，不在此大量展开。离线检查不能保证开机。\n");}
                runOnUiThread(()->toast("日志已保存"));
            }
        }catch(Exception e){runOnUiThread(()->toast(e.toString()));}},"file-picker").start();
    }
}
