"""Isolated app_process tests; never accesses the user's real unpacked ROM targets."""
from pathlib import Path
import subprocess,json,zipfile,os,hashlib,time,sys,shutil
ROOT=Path(__file__).resolve().parents[1]
if os.environ.get('RPM_ALLOW_DEVICE_TESTS') != '1':
 raise SystemExit('Device tests are disabled. Read tests/README.md before setting RPM_ALLOW_DEVICE_TESTS=1.')
SERIAL=os.environ.get('RPM_TEST_SERIAL')
if not SERIAL:raise SystemExit('Set RPM_TEST_SERIAL explicitly; no device is selected by default.')
ADB=Path(os.environ.get('RPM_ADB') or shutil.which('adb') or 'C:/adb-fastboot/adb.exe')
SDK=Path(os.environ.get('ANDROID_HOME',str(Path.home()/'AppData/Local/Android/Sdk')))
JDK=Path(os.environ.get('JAVA_HOME','C:/Program Files/Java/jdk-17'))/'bin';BT=SDK/'build-tools/35.0.0'
OUT=ROOT/'build/device-tests';OUT.mkdir(parents=True,exist_ok=True)
def run(args,check=True,timeout=300):
 p=subprocess.run([str(a) for a in args],capture_output=True,timeout=timeout)
 s=(p.stdout+p.stderr).decode('utf-8',errors='replace')
 if check and p.returncode:raise RuntimeError(s)
 return p.returncode,s
def adb(*args,**kw):return run([ADB,'-s',SERIAL,*args],**kw)
def shell(cmd,**kw):return adb('shell',cmd,**kw)
def q(s):return "'"+str(s).replace("'","'\\''")+"'"
def digest_tree(p):return {x.relative_to(p).as_posix():hashlib.sha256(x.read_bytes()).hexdigest() for x in p.rglob('*') if x.is_file()}
if __name__=='__main__':
 apk=os.environ.get('RPM_TEST_APK') or shell('pm path dev.rompolicy.merge')[1].strip().split('package:')[-1]
 if not apk.startswith(('/data/app/','/data/local/tmp/')):raise RuntimeError('Install or push test APK first')
 tool=apk.rsplit('/',1)[0]+'/lib/arm64'
 remote=json.loads((OUT/'last-device.json').read_text())['remote'] if os.environ.get('RPM_TEST_REUSE')=='1' else '/data/local/tmp/rpm-app-test-'+time.strftime('%Y%m%d-%H%M%S')
 shell('mkdir -p '+q(remote));(OUT/'last-device.json').write_text(json.dumps({'serial':SERIAL,'remote':remote,'apk':apk,'tools':tool},indent=2))
 classes=OUT/'classes';classes.mkdir(exist_ok=True)
 run([JDK/'javac.exe','-encoding','UTF-8','-source','8','-target','8','-cp',str(ROOT/'build/apk/classes')+';'+str(SDK/'platforms/android-35/android.jar'),'-d',classes,ROOT/'tests/CoreTests.java'])
 jar=OUT/'tests-classes.jar'
 with zipfile.ZipFile(jar,'w') as z:
  for p in classes.rglob('*.class'):z.write(p,p.relative_to(classes).as_posix())
 dex=OUT/'dex';dex.mkdir(exist_ok=True)
 run([JDK/'java.exe','-cp',BT/'lib/d8.jar','com.android.tools.r8.D8','--min-api','28','--lib',SDK/'platforms/android-35/android.jar','--classpath',ROOT/'build/apk/classes.jar','--output',dex,jar])
 testjar=OUT/'tests.jar'
 with zipfile.ZipFile(testjar,'w') as z:
  for p in dex.glob('*.dex'):z.write(p,p.name)
 adb('push',testjar,remote+'/tests.jar')
 code,report=shell('CLASSPATH='+q(apk+':'+remote+'/tests.jar')+' app_process /system/bin dev.rompolicy.merge.CoreTests '+q(apk),check=False)
 (OUT/'core-tests.txt').write_text(report,encoding='utf-8');print(report,flush=True)
 if code:sys.exit(code)
