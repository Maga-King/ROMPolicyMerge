"""Regression for the October OTA/debug incident. All writes use disposable test roots."""
from integration_tests import *

MINIMAL = '''(class file (read write open getattr))(class process (transition ptrace))
(classorder (file process))(sid kernel)(sidorder (kernel))
(user u)(role r)(role object_r)(type foo)(type bar)
(typeattribute domain)(typeattributeset domain (foo bar))
(sensitivity s0)(sensitivityorder (s0))(level s0 (s0))(levelrange range0 (s0 s0))
(roletype r foo)(roletype r bar)(roletype object_r foo)(roletype object_r bar)
(userrole u r)(userrole u object_r)(userlevel u s0)(userrange u range0)
(sidcontext kernel (u r foo range0))(allow foo self (file (read)))
'''


def fixture(name, full_source=False, undefined=False):
    f = OUT / (name + '-fixture')
    t, s = f / 'target', f / 'source'
    putfile(t, 'system/etc/selinux/plat_sepolicy.cil', MINIMAL)
    putfile(t, 'system/etc/selinux/mapping/202404.cil', '; mapping\n')
    putfile(t, 'system/etc/selinux/plat_file_contexts', '/platform u:object_r:foo:s0\n')
    for side in [t, s]:
        putfile(side, 'vendor/etc/selinux/plat_sepolicy_vers.txt', '202404\n')
        putfile(side, 'vendor/etc/selinux/vendor_sepolicy_debug.cil', '; debug lacks ordinary patch\n')
        putfile(side, 'vendor/etc/selinux/vendor_file_contexts', '')
    putfile(t, 'vendor/etc/selinux/vendor_sepolicy.cil',
            '(type saved_patch)(roletype object_r saved_patch)(allow foo saved_patch (file (read)))\n')
    putfile(t, 'vendor/etc/selinux/vendor_file_contexts', '/saved u:object_r:saved_patch:s0\n')
    putfile(s, 'vendor/etc/selinux/vendor_sepolicy.cil',
            '(type donor_patch)(roletype object_r donor_patch)(typeattribute base_typeattr_7)'
            '(typeattributeset base_typeattr_7 (donor_patch))(allow foo base_typeattr_7 (file (read write)))\n')
    putfile(s, 'vendor/etc/selinux/vendor_file_contexts', '/donor u:object_r:donor_patch:s0\n')
    if undefined:
        putfile(t, 'vendor/etc/selinux/vendor_file_contexts', '/missing u:object_r:no_definition:s0\n')
    if full_source:
        putfile(s, 'system/etc/selinux/plat_sepolicy.cil', MINIMAL + '(type platform_patch)(roletype object_r platform_patch)\n')
        putfile(s, 'system/etc/selinux/mapping/202404.cil', '; mapping\n')
        putfile(s, 'system/etc/selinux/plat_file_contexts', '/platform_new u:object_r:platform_patch:s0\n')
    adb('push', f, remote + '/' + name)
    return t, s


def job_result(name):
    return collect(name, name + '-results')


if __name__ == '__main__':
    tag = 'ota-' + time.strftime('%H%M%S')
    t, s = fixture(tag)
    before, donor = digest_tree(t), digest_tree(s)
    req(tag+'-off', remote+'/'+tag+'/target', remote+'/'+tag+'/source', repair_debug=False)
    code, log = worker(tag+'-off')
    check(code != 0, 'unrepaired debug failure is reproducible')
    results = job_result(tag+'-off')
    validation = json.loads((results/'validation.json').read_text())
    check(validation['normal']['contexts_valid'] and not validation['debug']['contexts_valid'], 'report distinguishes normal pass from debug failure')
    diag = json.loads((results/'contexts-invalid-debug.json').read_text())
    check(any(r['type']=='saved_patch' and r['normal_cil_declares'] and not r['debug_cil_declares'] for r in diag['references']), 'diagnosis identifies missing debug declaration and original context line')
    check(digest_tree(collect(tag+'/target',tag+'-off-target')) == before, 'debug validation failure writes nothing')

    req(tag+'-preview', remote+'/'+tag+'/target', remote+'/'+tag+'/source', write_scope='vendor_odm', validate_only=True)
    code, log = worker(tag+'-preview');check(code == 0, 'partial donor and normal-to-debug supplement compile both variants')
    results = job_result(tag+'-preview')
    check(not (results/'transaction.json').exists() and digest_tree(collect(tag+'/target',tag+'-preview-target'))==before, 'preview creates no transaction and leaves target bytes untouched')
    check('未写回' in json.loads((results/'result.json').read_text())['message'], 'preview UI result does not claim writeback')

    req(tag+'-write', remote+'/'+tag+'/target', remote+'/'+tag+'/source', write_scope='vendor_odm')
    code, log = worker(tag+'-write');check(code == 0, 'partial donor merge writes after both variants validate')
    final=collect(tag+'/target',tag+'-final');after=digest_tree(final)
    debug=(final/'vendor/etc/selinux/vendor_sepolicy_debug.cil').read_text()
    check('(type saved_patch)' in debug and '(type donor_patch)' in debug and 'allow foo' in debug, 'target existing patch and donor types arrive with rules, not empty type stubs')
    check(digest_tree(collect(tag+'/source',tag+'-donor-final'))==donor, 'partial donor is not modified or filled with borrowed system')
    results=job_result(tag+'-write');txn=json.loads((results/'transaction.json').read_text())
    check(all(r['path'].startswith(('vendor/','odm/')) for r in txn['files']), 'OTA write manifest is limited to vendor and odm')
    req(tag+'-repeat',remote+'/'+tag+'/target',remote+'/'+tag+'/source',write_scope='vendor_odm')
    code,log=worker(tag+'-repeat');check(code==0,'repeat merge compiles')
    check(digest_tree(collect(tag+'/target',tag+'-repeated'))==after,'repeat repair is byte-idempotent')
    code,log=worker(tag+'-write');check(code!=0,'reusing a job cannot overwrite its original backup')
    code,log=worker(tag+'-write','restore');check(code==0,'previous backup remains restorable after rejected job reuse')
    check(digest_tree(collect(tag+'/target',tag+'-restored'))==before,'restoration returns every original byte')

    name=tag+'-platform';t,s=fixture(name,full_source=True);before=digest_tree(t)
    req(name+'-job',remote+'/'+name+'/target',remote+'/'+name+'/source',write_scope='vendor_odm')
    code,log=worker(name+'-job');check(code==0,'OTA mode routes new platform rules and labels into existing vendor files')
    final=collect(name+'/target',name+'-final');after=digest_tree(final)
    check(all(after[p]==h for p,h in before.items() if p.startswith('system/')),'platform files remain byte-for-byte unchanged')
    check('/platform_new' in (final/'vendor/etc/selinux/vendor_file_contexts').read_text(),'platform labels are retained in an existing init-consumed vendor context file')

    name=tag+'-undefined';t,s=fixture(name,undefined=True);before=digest_tree(t)
    req(name+'-job',remote+'/'+name+'/target',remote+'/'+name+'/source',write_scope='vendor_odm')
    code,log=worker(name+'-job');check(code!=0,'a truly undefined official label still stops writeback')
    results=job_result(name+'-job')
    diag=json.loads((results/'contexts-invalid-normal.json').read_text())
    check(any(r['type']=='no_definition' and not r['normal_cil_declares'] and not r['debug_cil_declares'] for r in diag['references']),'truly missing definitions are distinguished from variant mismatch')
    check(digest_tree(collect(name+'/target',name+'-unchanged'))==before,'undefined labels are neither deleted nor replaced with dummy types')
    print('OTA_DEBUG_TESTS_PASS')
