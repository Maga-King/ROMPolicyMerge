"""Replay on copies only. Positional ROM roots are read-only, never worker targets."""
from integration_tests import *
import argparse

if __name__ == '__main__':
    if os.environ.get('RPM_ALLOW_REAL_REPLAY') != '1':
        raise SystemExit('Real policy replay is disabled. Read tests/README.md and explicitly set RPM_ALLOW_REAL_REPLAY=1.')
    parser = argparse.ArgumentParser()
    parser.add_argument('target_rom')
    parser.add_argument('source_rom')
    parser.add_argument('--extra')
    args = parser.parse_args()
    name = 'real-ota-' + time.strftime('%Y%m%d-%H%M%S')
    stage = remote + '/' + name
    rels = ['system/system/etc/selinux', 'system/etc/selinux', 'system_ext/etc/selinux',
            'product/etc/selinux', 'vendor/etc/selinux', 'odm/etc/selinux']
    def fingerprints(root):
        code, text = shell('find '+q(root)+' -type f -exec sha256sum {} +')
        return text
    before = {}
    for side, rom in [('target',args.target_rom),('source',args.source_rom)]:
        for rel in rels:
            code, _ = shell('test -d '+q(rom+'/'+rel), check=False)
            if code: continue
            before[rom+'/'+rel] = fingerprints(rom+'/'+rel)
            shell('mkdir -p '+q(stage+'/'+side+'/'+rel.rsplit('/',1)[0])+' && cp -a '+q(rom+'/'+rel)+' '+q(stage+'/'+side+'/'+rel))
    fixture = collect(name+'/target',name+'-before')
    baseline = digest_tree(fixture)
    extra={}
    if args.extra:
        shell('cp '+q(args.extra)+' '+q(stage+'/extra.rule'))
        extra={'extra':stage+'/extra.rule','format':'auto'}
    req(name+'-job',stage+'/target',stage+'/source',write_scope='vendor_odm',**extra)
    code,log=worker(name+'-job');check(code==0,'real split policies compile and contexts validate in both variants')
    result=collect(name+'-job',name+'-job-results')
    validation=json.loads((result/'validation.json').read_text(encoding='utf8'))
    check(all(validation[v]['compiled'] and validation[v]['roundtrip'] and validation[v]['contexts_valid'] for v in ['normal','debug']), 'real normal/debug readback and all contexts pass')
    final=collect(name+'/target',name+'-after');final_hash=digest_tree(final)
    check(all(final_hash.get(p)==h for p,h in baseline.items() if p.startswith(('system/','system_ext/','product/'))),'real platform files remain byte-exact in OTA mode')
    check(all(fingerprints(root)==h for root,h in before.items()),'all original ROM policy inputs remain unchanged')
    req(name+'-repeat',stage+'/target',stage+'/source',write_scope='vendor_odm',**extra)
    code,log=worker(name+'-repeat');check(code==0,'second real merge validates')
    check(digest_tree(collect(name+'/target',name+'-repeated'))==final_hash,'real merge is byte-idempotent')
    if (result/'transaction.json').exists():
        code,log=worker(name+'-job','restore');check(code==0,'real isolated transaction restores')
        check(digest_tree(collect(name+'/target',name+'-restored'))==baseline,'real restore is byte-exact')
    print('REAL_OTA_REPLAY_PASS '+name)
