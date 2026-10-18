"""Build ARM64 policy tools from the pinned AOSP source."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
VERSION = ET.parse(ROOT / 'app/AndroidManifest.xml').getroot().attrib['{http://schemas.android.com/apk/res/android}versionName']
LOCK = json.loads((ROOT / ('build-config/release-' + VERSION + '.json')).read_text(encoding='utf-8'))
LIB = ROOT / 'third_party/selinux/libsepol'
OUT = ROOT / 'build/native'
NDK = Path(os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT') or
           'E:/MIO/tools/ndk-r27d-clean/android-ndk-r27d')
HOST = 'windows-x86_64' if os.name == 'nt' else 'linux-x86_64'
BIN = NDK / 'toolchains/llvm/prebuilt' / HOST / 'bin'
EXE = '.exe' if os.name == 'nt' else ''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    result = subprocess.run(list(map(str, args)), capture_output=True)
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr).decode(errors='replace'))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    lexer = ROOT / 'native/generated/cil_lexer.c'
    if sha(lexer) != LOCK['generated_lexer_sha256']:
        raise RuntimeError('Generated lexer differs from the pinned source')
    properties = (NDK / 'source.properties').read_text()
    if 'Pkg.Revision = ' + LOCK['toolchains']['ndk'] not in properties:
        raise RuntimeError('Use NDK ' + LOCK['toolchains']['ndk'])
    bp = (LIB / 'Android.bp').read_text()
    chunk = bp.split('    srcs: [', 1)[1].split('    ],', 1)[0]
    sources = [LIB / name for name in re.findall(r'"([^\"]+\.c)"', chunk)] + [lexer]
    flags = ['--target=aarch64-linux-android28', '-O2', '-D_GNU_SOURCE', '-DANDROID',
             '-fPIC', '-ffunction-sections', '-fdata-sections',
             '-Wno-unused-command-line-argument']
    # libsepol contains __FILE__ in one diagnostic. Retain the historical
    # compiler spelling without depending on the checkout's physical path.
    historical = 'F:\\SEPOLICY\\RomPolicyMerge'.replace('\\\\', '\\')
    flags += ['-ffile-prefix-map=' + str(ROOT) + '=' + historical,
              '-ffile-prefix-map=' + ROOT.as_posix() + '=' + historical]
    flags += ['-I' + str(path) for path in
              (LIB / 'include', LIB / 'cil/include', LIB / 'cil/src', LIB / 'src')]

    def compile_one(source):
        relative = source.relative_to(ROOT).as_posix()
        obj = OUT / (source.stem + '_' + hashlib.sha256(relative.encode()).hexdigest()[:8] + '.o')
        run([BIN / ('clang' + EXE), *flags, '-c', source, '-o', obj])
        return obj

    with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 2)) as pool:
        objects = list(pool.map(compile_one, sources))
    archive = OUT / 'libsepol.a'
    if archive.exists():
        archive.unlink()
    run([BIN / ('llvm-ar' + EXE), 'rcs', archive, *objects])
    dest = ROOT / 'app/lib/arm64-v8a'
    dest.mkdir(parents=True, exist_ok=True)
    expected = {item['name']: item['sha256'] for item in LOCK['entries']}
    for name, source in (
            ('secilc', ROOT / 'third_party/selinux/secilc/secilc.c'),
            ('policytool', ROOT / 'native/policytool.c')):
        obj = compile_one(source)
        output = dest / ('lib' + name + '.so')
        run([BIN / ('clang' + EXE), '--target=aarch64-linux-android28', '-static',
             obj, archive, '-Wl,--gc-sections', '-Wl,-z,max-page-size=16384', '-o', output])
        run([BIN / ('llvm-strip' + EXE), output])
        digest = sha(output)
        print(name, output.stat().st_size, digest, flush=True)
        if digest != expected['lib/arm64-v8a/' + output.name]:
            raise RuntimeError(name + ' is not byte-identical to the pinned release')
    (OUT / 'provenance.json').write_text(json.dumps({
        'repository': 'https://android.googlesource.com/platform/external/selinux',
        'commit': LOCK['selinux_commit'], 'abi': 'arm64-v8a', 'api': 28,
        'static': True}, indent=2), encoding='utf-8')
    print('Native tools match the pinned release.')


if __name__ == '__main__':
    main()
