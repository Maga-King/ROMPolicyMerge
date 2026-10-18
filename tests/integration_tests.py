from device_tests import *
STATE=json.loads((OUT/'last-device.json').read_text());remote=STATE['remote']
installed=shell('pm path dev.rompolicy.merge')[1].strip().split('package:')[-1]
apk=os.environ.get('RPM_TEST_APK') or installed;tool=installed.rsplit('/',1)[0]+'/lib/arm64'
def putfile(root,rel,text):
 p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf-8',newline='\n')
def req(job,target,source,**options):
 p=OUT/(job+'-request.json');p.write_text(json.dumps(dict(target=target,source=source,hardware=True,permissive=True,**options)),encoding='utf-8')
 shell('mkdir -p '+q(remote+'/'+job));adb('push',p,remote+'/'+job+'/request.json')
def worker(job,mode='merge'):
 heap=os.environ.get('RPM_TEST_HEAP','512m')
 if heap not in ('256m','512m','768m','1024m','1536m'):raise ValueError('RPM_TEST_HEAP must be 256m, 512m, 768m, 1024m or 1536m')
 code,s=shell('/apex/com.android.art/bin/dalvikvm64 -Xmx'+heap+' -XX:HeapGrowthLimit='+heap+' -cp '+q(apk)+' dev.rompolicy.merge.RootWorker '+q(remote+'/'+job)+' '+q(tool)+' '+mode,check=False,timeout=1800)
 (OUT/(job+'-'+mode+'.txt')).write_text(s,encoding='utf-8');print(s,flush=True);return code,s
def collect(path,name):
 p=OUT/name;p.mkdir(exist_ok=True);adb('pull',remote+'/'+path+'/.',p);return p
def check(v,msg):
 if not v:raise AssertionError(msg)
 print('PASS '+msg,flush=True)
if __name__=='__main__':
 minimal='''(class file (read write open getattr))(class process (transition ptrace))(class property_service (set))(class binder (call transfer impersonate set_context_mgr))
(classorder (file process property_service binder))(sid kernel)(sidorder (kernel))
(user u)(role r)(role object_r)(type foo)(type bar)(typeattribute domain)(typeattributeset domain (foo bar))
(sensitivity s0)(sensitivityorder (s0))(level s0 (s0))(levelrange range0 (s0 s0))
(roletype r foo)(roletype r bar)(roletype object_r foo)(roletype object_r bar)
(userrole u r)(userrole u object_r)(userlevel u s0)(userrange u range0)
(sidcontext kernel (u r foo range0))(allow foo self (file (read)))
'''
 fixture=OUT/'small-fixture'
 for side,vers in [('target','202404'),('source','202504')]:
  root=fixture/side
  putfile(root,'system/etc/selinux/plat_sepolicy.cil',minimal+('(neverallow foo bar (file (write)))\n' if side=='target' else ''))
  putfile(root,'system/etc/selinux/mapping/'+vers+'.cil','; mapping\n')
  putfile(root,'vendor/etc/selinux/plat_sepolicy_vers.txt',vers+'\n')
  putfile(root,'vendor/etc/selinux/vendor_sepolicy.cil','; original\n' if side=='target' else '(allow foo bar (file (read write)))(allow foo bar (process (ptrace)))(neverallow bar foo (file (read)))(type new_type)(roletype object_r new_type)(roletype r new_type)\n')
  putfile(root,'vendor/etc/selinux/vendor_property_contexts','persist.demo u:object_r:foo:s0 exact string\n' if side=='target' else 'persist.demo u:object_r:bar:s0 exact string\npersist.new u:object_r:new_type:s0 exact bool\n')
  putfile(root,'vendor/etc/selinux/vendor_file_contexts','/vendor/demo u:object_r:foo:s0\n' if side=='target' else '/vendor/new u:object_r:new_type:s0\n')
 putfile(fixture/'target','vendor/etc/selinux/precompiled_sepolicy','test-cache-not-a-live-policy\n')
 before=digest_tree(fixture/'target');donor=digest_tree(fixture/'source')
 adb('push',fixture,remote+'/small')
 req('small-job',remote+'/small/target',remote+'/small/source')
 code,s=worker('small-job');check(code==0,'end-to-end compile and automatic writeback')
 final=collect('small/target','small-final');after=digest_tree(final)
 check('precompiled_sepolicy' not in '\n'.join(after),'old compiled cache removed only after successful validation')
 policy=(final/'vendor/etc/selinux/vendor_sepolicy.cil').read_text();check('(allow foo bar (file (read write)))' in policy,'allow violating retained neverallow survives full secilc -N')
 prop=(final/'vendor/etc/selinux/vendor_property_contexts').read_text();check('persist.demo u:object_r:foo:s0' in prop and 'persist.demo u:object_r:bar:s0' not in prop and 'persist.new' in prop,'context conflict target wins and new key merged')
 donor_final=collect('small/source','small-source-final');check(digest_tree(donor_final)==donor,'source remains byte-for-byte unchanged')
 job=collect('small-job','small-job-result');check('CONTEXT_CONFLICT' in (job/'audit.jsonl').read_text(),'context conflicts saved')
 check('roundtrip_ok' in ''.join(x.read_text(errors='replace') for x in (job/'commands').glob('*.log')),'binary serialize/readback succeeds')
 code,s=worker('small-job','restore');check(code==0,'restore completes')
 restored=collect('small/target','small-restored');check(digest_tree(restored)==before,'restore is byte-exact including old compiled cache')
 bad=OUT/'bad-extra.rule';bad.write_text('unknown_macro(foo)\n');adb('push',bad,remote+'/bad-extra.rule')
 req('bad-job',remote+'/small/target',remote+'/small/source',extra=remote+'/bad-extra.rule',format='te');code,s=worker('bad-job');check(code!=0,'unsupported extra rule fails closed')
 unchanged=collect('small/target','small-unchanged');check(digest_tree(unchanged)==before,'failed merge does not modify target')
 compat=OUT/'compat-extra.rule';compat.write_text('allow foo bar binder { ioctl call }\nallow foo bar binder { ioctl }\nallow foo bar missing_class read\n',encoding='utf8');adb('push',compat,remote+'/compat-extra.rule')
 req('compat-extra-job',remote+'/small/target',remote+'/small/source',extra=remote+'/compat-extra.rule',format='magisk')
 code,s=worker('compat-extra-job');check(code==0,'invalid extra permission no longer aborts whole merge')
 check('编译阶段' in s and '额外规则筛选完成' in s,'Chinese compiler and filtering progress emitted')
 final=collect('small/target','compat-final');policy=(final/'vendor/etc/selinux/vendor_sepolicy.cil').read_text()
 check('(allow foo bar (binder (call)))' in policy and 'ioctl' not in policy,'only invalid permission removed after full compile')
 code,s=worker('compat-extra-job','restore');check(code==0,'compat regression restore completes')
 restored=collect('small/target','compat-restored');check(digest_tree(restored)==before,'compat regression restore byte-exact')
 variants=OUT/('variant-fixture-'+time.strftime('%H%M%S'))
 for side in ['target','source']:
  root=variants/side
  putfile(root,'system/etc/selinux/plat_sepolicy.cil',minimal+'(typeattribute normal_only)\n')
  putfile(root,'system/etc/selinux/plat_sepolicy_debug.cil',minimal+'(typeattribute debug_only)\n')
  putfile(root,'system/etc/selinux/mapping/202404.cil','; mapping\n')
  putfile(root,'vendor/etc/selinux/plat_sepolicy_vers.txt','202404\n')
  putfile(root,'vendor/etc/selinux/vendor_sepolicy.cil','; vendor normal\n')
  putfile(root,'vendor/etc/selinux/vendor_sepolicy_debug.cil','; vendor debug\n')
  putfile(root,'system_ext/etc/selinux/system_ext_sepolicy.cil','; shared target\n' if side=='target' else '(typeattributeset normal_only (foo))(allow normal_only bar (file (write)))\n')
  if side=='source':putfile(root,'system_ext/etc/selinux/system_ext_sepolicy_debug.cil','(typeattributeset debug_only (foo))(allow debug_only bar (file (write)))\n')
 beforeVariants=digest_tree(variants/'target');adb('push',variants,remote+'/variants')
 req('variant-job',remote+'/variants/target',remote+'/variants/source');code,s=worker('variant-job');check(code==0,'both variants compile with distinct platform-only attributes')
 final=collect('variants/target','variants-final')
 normal=(final/'vendor/etc/selinux/vendor_sepolicy.cil').read_text();debug=(final/'vendor/etc/selinux/vendor_sepolicy_debug.cil').read_text()
 check('normal_only' in normal and 'debug_only' not in normal and 'debug_only' in debug and 'normal_only' not in debug,'normal/debug additions remain isolated in both directions')
 check((final/'system_ext/etc/selinux/system_ext_sepolicy.cil').read_text()=='; shared target\n','shared file is not contaminated by variant-only additions')
 code,s=worker('variant-job','restore');check(code==0,'variant restore completes')
 check(digest_tree(collect('variants/target','variants-restored'))==beforeVariants,'variant restore byte-exact')
 print('INTEGRATION_PASS',flush=True)
