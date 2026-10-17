"""Reproduce the signed 1.0.4 APK using the same payload and ZIP metadata."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent
LOCK = json.loads((ROOT / 'build-config/release-1.0.4.json').read_text(encoding='utf-8'))
SDK = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or
           Path.home() / 'AppData/Local/Android/Sdk')
JDK = Path(os.environ.get('JAVA_HOME', 'C:/Program Files/Java/jdk-17')) / 'bin'
BT = SDK / 'build-tools/35.0.0'
OUT = ROOT / 'build/apk'
EXE = '.exe' if os.name == 'nt' else ''
CERTIFICATE_SHA256 = '499b3a4f96926c4ee4b8648e0f25768ee41ea6ccbaf5b651a953396853e754aa'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, env=None):
    result = subprocess.run(list(map(str, args)), capture_output=True, env=env)
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr).decode(errors='replace'))
    return (result.stdout + result.stderr).decode(errors='replace')


def write_entry(archive, path, record):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != record['sha256']:
        raise RuntimeError('Payload differs: ' + record['name'])
    info = zipfile.ZipInfo(record['name'], tuple(record['date_time']))
    info.compress_type = record['compression']
    info.create_system = record['create_system']
    info.external_attr = record['external_attr']
    archive.writestr(info, data)


def main():
    if os.name != 'nt':
        raise RuntimeError('This historical release uses Windows Android build tools for exact reproduction')
    for name, expected in LOCK['tool_files'].items():
        if sha(SDK / name) != expected:
            raise RuntimeError('Android SDK tool differs: ' + name)
    attributes = ET.parse(ROOT / 'app/AndroidManifest.xml').getroot().attrib
    version = attributes['{http://schemas.android.com/apk/res/android}versionName']
    if version != LOCK['version']:
        raise RuntimeError('Update the build lock for a new version')
    OUT.mkdir(parents=True, exist_ok=True)
    classes = OUT / 'classes'
    # This directory contains generated output only. A fresh class directory
    # prevents removed Java sources from remaining in the APK.
    if classes.exists():
        shutil.rmtree(classes)
    classes.mkdir()
    android = SDK / 'platforms/android-35/android.jar'
    run([JDK / ('javac' + EXE), '-encoding', 'UTF-8', '-source', '8', '-target', '8',
         '-cp', android, '-d', classes, *[ROOT / name for name in LOCK['java_sources']]])
    jar = OUT / 'classes.jar'
    with zipfile.ZipFile(jar, 'w') as archive:
        for path in sorted(classes.rglob('*.class')):
            archive.write(path, path.relative_to(classes).as_posix())
    dex = OUT / 'dex'
    dex.mkdir(exist_ok=True)
    run([JDK / ('java' + EXE), '-cp', BT / 'lib/d8.jar', 'com.android.tools.r8.D8',
         '--min-api', '28', '--lib', android, '--output', dex, jar])
    unsigned = OUT / 'unsigned.apk'
    run([BT / ('aapt2' + EXE), 'link', '-o', unsigned, '-I', android,
         '--manifest', ROOT / 'app/AndroidManifest.xml', '--min-sdk-version', '28',
         '--target-sdk-version', '35', '--auto-add-overlay'])
    with zipfile.ZipFile(unsigned, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
        for record in LOCK['entries']:
            name = record['name']
            if name in ('AndroidManifest.xml', 'resources.arsc'):
                if hashlib.sha256(archive.read(name)).hexdigest() != record['sha256']:
                    raise RuntimeError('Android resource differs: ' + name)
                continue
            if name == 'classes.dex':
                path = dex / name
            elif name.startswith('lib/'):
                path = ROOT / 'app' / name
            elif name.startswith('assets/'):
                path = ROOT / 'app' / name
            else:
                raise RuntimeError('Unknown packaging entry: ' + name)
            write_entry(archive, path, record)
    aligned = OUT / 'aligned.apk'
    run([BT / ('zipalign' + EXE), '-f', '-p', '4', unsigned, aligned])
    key = Path(os.environ.get('ROMPOLICY_KEYSTORE', str(ROOT / 'signing/local-release.jks')))
    if not key.is_file():
        raise RuntimeError('Set ROMPOLICY_KEYSTORE to the existing release key')
    env = os.environ.copy()
    # The historical key uses this password; the keystore itself is private
    # and is supplied to Actions only through an encrypted repository secret.
    env.setdefault('ROMPOLICY_STORE_PASSWORD', 'rompolicy-local')
    env.setdefault('ROMPOLICY_KEY_PASSWORD', env['ROMPOLICY_STORE_PASSWORD'])
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    apk = dist / ('ROMPolicyMerge-v' + version + '-arm64.apk')
    run([JDK / ('java' + EXE), '-jar', BT / 'lib/apksigner.jar', 'sign', '--ks', key,
         '--ks-key-alias', 'rompolicy', '--ks-pass', 'env:ROMPOLICY_STORE_PASSWORD',
         '--key-pass', 'env:ROMPOLICY_KEY_PASSWORD', '--out', apk, aligned], env=env)
    verification = run([JDK / ('java' + EXE), '-jar', BT / 'lib/apksigner.jar',
                        'verify', '--verbose', '--print-certs', apk])
    if CERTIFICATE_SHA256 not in verification:
        raise RuntimeError('Unexpected signing certificate')
    data = apk.read_bytes()
    md5, sha256 = hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()
    manifest = {'file': apk.name, 'bytes': len(data), 'md5': md5, 'sha256': sha256,
                'certificate_sha256': CERTIFICATE_SHA256}
    (dist / 'checksums.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    (dist / 'SHA256SUMS.txt').write_text(sha256 + '  ' + apk.name + '\n', encoding='utf-8')
    print(json.dumps(manifest, indent=2))
    if md5 != LOCK['expected_md5'] or sha256 != LOCK['expected_sha256']:
        raise RuntimeError('Signed APK is not byte-identical to the pinned release')
    print('Signed APK matches the pinned release byte for byte.')


if __name__ == '__main__':
    main()
