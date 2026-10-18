"""Different ROMs reuse generated attribute numbers; their members must stay separate."""
from ota_debug_tests import *
import re

if __name__ == '__main__':
    name = 'namespaces-' + time.strftime('%H%M%S')
    t, s = fixture(name)
    # The target itself has an ordinary generated attribute. Debug repair must
    # remain stable after the ordinary file acquires imported additions.
    putfile(t, 'vendor/etc/selinux/vendor_sepolicy.cil',
            (t/'vendor/etc/selinux/vendor_sepolicy.cil').read_text(encoding='utf8') +
            '(typeattribute base_typeattr_9)(typeattributeset base_typeattr_9 (saved_patch))'
            '(allow foo base_typeattr_9 (file (getattr)))\n')
    adb('push', t/'vendor/etc/selinux/vendor_sepolicy.cil',
        remote+'/'+name+'/target/vendor/etc/selinux/vendor_sepolicy.cil')
    target = remote+'/'+name+'/target'
    req(name+'-a', target, remote+'/'+name+'/source', write_scope='vendor_odm')
    code, _ = worker(name+'-a'); check(code == 0, 'first donor compiles')
    donor_b = OUT/(name+'-donor-b')
    putfile(donor_b, 'vendor/etc/selinux/plat_sepolicy_vers.txt', '202404\n')
    putfile(donor_b, 'vendor/etc/selinux/vendor_sepolicy.cil',
            '(type donor_two)(roletype object_r donor_two)'
            '(typeattribute base_typeattr_7)(typeattributeset base_typeattr_7 (donor_two))'
            '(allow bar base_typeattr_7 (file (open)))\n')
    putfile(donor_b, 'vendor/etc/selinux/vendor_file_contexts', '/two u:object_r:donor_two:s0\n')
    adb('push', donor_b, remote+'/'+name+'/donor-b')
    req(name+'-b', target, remote+'/'+name+'/donor-b', write_scope='vendor_odm')
    code, _ = worker(name+'-b'); check(code == 0, 'second donor compiles')
    final = collect(name+'/target',name+'-final')
    for variant in ['', '_debug']:
        policy = (final/('vendor/etc/selinux/vendor_sepolicy'+variant+'.cil')).read_text(encoding='utf8')
        definitions = re.findall(r'\(typeattributeset (rpm_\S+_base_typeattr_7) \((donor_patch|donor_two)\)\)', policy)
        attrs = {member: {attr for attr, value in definitions if value == member}
                 for member in ['donor_patch', 'donor_two']}
        check(bool(attrs['donor_patch']) and bool(attrs['donor_two']) and
              attrs['donor_patch'].isdisjoint(attrs['donor_two']),
              'different donor attribute memberships stay separate: '+(variant or 'normal'))
    before = digest_tree(final)
    req(name+'-repeat', target, remote+'/'+name+'/donor-b', write_scope='vendor_odm')
    code, _ = worker(name+'-repeat'); check(code == 0, 'second donor repeat compiles')
    check(digest_tree(collect(name+'/target',name+'-repeated')) == before,
          'repeat is byte-exact even with original target generated attributes')
    print('SOURCE_NAMESPACE_TESTS_PASS')
