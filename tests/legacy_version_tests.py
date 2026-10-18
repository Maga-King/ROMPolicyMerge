from integration_tests import *
import shutil
if __name__=='__main__':
 for version,pv in [('28.0','30'),('30.0','30'),('33.0','33')]:
  slug=version.replace('.','_');fixture=OUT/('legacy-'+slug+'-'+time.strftime('%Y%m%d-%H%M%S'))
  shutil.copytree(OUT/'small-fixture',fixture,dirs_exist_ok=True)
  for side,old,new in [('target','202404',version),('source','202504','34.0')]:
   root=fixture/side;mapping=root/'system/etc/selinux/mapping'
   (mapping/(old+'.cil')).rename(mapping/(new+'.cil'))
   putfile(root,'vendor/etc/selinux/plat_sepolicy_vers.txt',new+'\n')
   putfile(root,'system/etc/selinux/mapping/'+new+'.cil','(typeattribute foo_'+new.replace('.','_')+')(typeattributeset foo_'+new.replace('.','_')+' (foo))\n')
  target=fixture/'target';source=fixture/'source'
  path=target/'vendor/etc/selinux/vendor_sepolicy.cil';path.write_text('(dontaudit bar foo (file (read)))\n')
  path=source/'vendor/etc/selinux/vendor_sepolicy.cil';path.write_text(path.read_text()+'(allow foo_34_0 bar (file (open)))(dontaudit foo bar (file (open)))(dontauditx foo bar (ioctl file (0x12)))\n')
  adb('push',fixture,remote+'/legacy-'+slug)
  job='legacy-job-'+slug
  req(job,remote+'/legacy-'+slug+'/target',remote+'/legacy-'+slug+'/source',policy_version=pv)
  code,s=worker(job);check(code==0,'legacy '+version+' full compile at binary '+pv)
  result=collect('legacy-'+slug+'/target','legacy-final-'+slug)
  v=(result/'vendor/etc/selinux/vendor_sepolicy.cil').read_text()
  check('(allow foo_'+slug+' bar (file (open)))' in v,'source 34.0 references adapt to '+version)
  check('(dontaudit bar foo (file (read)))' in v and '(dontaudit foo bar' not in v and '(dontauditx ' not in v,'old dontaudit retained and both new forms excluded')
  code,s=worker(job,'restore');check(code==0,'legacy '+version+' restore')
  restored=collect('legacy-'+slug+'/target','legacy-restored-'+slug);check(digest_tree(restored)==digest_tree(target),'legacy '+version+' restored byte-exact')
 print('MULTI_VERSION_FIXTURE_PASS')
