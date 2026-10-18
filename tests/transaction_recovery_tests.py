"""Replay interrupted staging/restore without killing a real writer or touching ROMs."""
from ota_debug_tests import *
import uuid

if __name__ == '__main__':
    name = 'recovery-' + time.strftime('%H%M%S')
    target, source = fixture(name)
    baseline = digest_tree(target)
    root = remote+'/'+name+'/target'
    job = name+'-job'
    req(job, root, remote+'/'+name+'/source', write_scope='vendor_odm')
    code, _ = worker(job); check(code == 0, 'recovery fixture writes successfully')
    result = collect(job,job+'-result')
    txn = json.loads((result/'transaction.json').read_text(encoding='utf8'))
    writes = [row for row in txn['files'] if row['after'] is not None]
    check(bool(writes) and all('staging' in row for row in writes), 'each write journals its exact staging path')
    row = writes[0]
    row['restore_staging'] = row['path']+'.rpm-restore-'+str(uuid.uuid4())
    for field in ['staging','restore_staging']:
        shell('printf %s partial > '+q(root+'/'+row[field]))
    # Unknown files with a similar suffix are never a cleanup target.
    untracked = row['path']+'.rpm-'+str(uuid.uuid4())
    shell('printf %s user-file > '+q(root+'/'+untracked))
    before_restore = digest_tree(collect(name+'/target',name+'-interrupted'))
    txn['status'] = 'writing'
    original_stage = row['staging']
    row['staging'] = '../../outside.rpm-'+str(uuid.uuid4())
    local = OUT/(job+'-journal.json')
    def upload():
        local.write_text(json.dumps(txn),encoding='utf8')
        adb('push',local,remote+'/'+job+'/transaction.json')
    upload()
    code, _ = worker(job,'restore'); check(code != 0, 'invalid staging path is rejected before recovery')
    check(digest_tree(collect(name+'/target',name+'-rejected')) == before_restore,
          'invalid journal causes no partial cleanup or rollback')
    row['staging'] = original_stage
    upload()
    code, _ = worker(job,'restore'); check(code == 0, 'interrupted staging and restore recover successfully')
    restored = digest_tree(collect(name+'/target',name+'-restored'))
    expected = dict(baseline)
    expected[untracked] = hashlib.sha256(b'user-file').hexdigest()
    check(restored == expected, 'restoration is byte-exact and removes only journaled temporary files')
    print('TRANSACTION_RECOVERY_TESTS_PASS')
