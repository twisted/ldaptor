"""
Test cases for ldaptor.protocols.ldap.autofill.sambaAccount module.
"""

import sets
from twisted.trial import unittest
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.protocols.ldap.autofill import sambaAccount, sambaSamAccount
from ldaptor import testutil

class LDAPAutoFill_sambaAccount(unittest.TestCase):
    def testMustHaveObjectClass(self):
        """Test that Autofill_samba fails unless object is a sambaAccount."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['something', 'other'],
            })
        autoFiller = sambaAccount.Autofill_samba()
        d = o.addAutofiller(autoFiller)

        def eb(val):
            client.assertNothingSent()
            val.trap(sambaAccount.ObjectMissingObjectClassException)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def testDefaultSetting(self):
        """Test that fields get their default values."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['sambaAccount', 'other'],
            })
        d = o.addAutofiller(sambaAccount.Autofill_samba())

        def cb(dummy):
            client.assertNothingSent()

            self.failUnless('acctFlags' in o)
            self.failUnlessEqual(o['acctFlags'], ['[UX         ]'])

            self.failUnless('pwdLastSet' in o)
            self.failUnlessEqual(o['pwdLastSet'], ['0'])
            self.failUnless('logonTime' in o)
            self.failUnlessEqual(o['logonTime'], ['0'])
            self.failUnless('logoffTime' in o)
            self.failUnlessEqual(o['logoffTime'], ['0'])
            self.failUnless('pwdCanChange' in o)
            self.failUnlessEqual(o['pwdCanChange'], ['0'])
            self.failUnless('pwdMustChange' in o)
            self.failUnlessEqual(o['pwdMustChange'], ['0'])

        d.addCallback(cb)
        return d

    def testRid(self):
        """Test that rid field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['sambaAccount', 'other'],
            })
        d = o.addAutofiller(sambaAccount.Autofill_samba())

        def cb(dummy):
            client.assertNothingSent()

            o['uidNumber'] = ['1000']
            self.failUnless('rid' in o)
            self.failUnlessEqual(o['rid'], [str(2 * 1000 + 1000)])
            o['uidNumber'] = ['1001']
            self.failUnlessEqual(o['rid'], [str(2 * 1001 + 1000)])
            o['uidNumber'] = ['1002']
            self.failUnlessEqual(o['rid'], [str(2 * 1002 + 1000)])
            o['uidNumber'] = ['2000']
            self.failUnlessEqual(o['rid'], [str(2 * 2000 + 1000)])
            o['uidNumber'] = ['3000']
            self.failUnlessEqual(o['rid'], [str(2 * 3000 + 1000)])
            o['uidNumber'] = ['0']
            self.failUnlessEqual(o['rid'], [str(2 * 0 + 1000)])
            o['uidNumber'] = ['16000']
            self.failUnlessEqual(o['rid'], [str(2 * 16000 + 1000)])

        d.addCallback(cb)
        return d

    def testPrimaryGroupId(self):
        """Test that primaryGroupID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                            dn='cn=foo,dc=example,dc=com',
                                            attributes={
            'objectClass': ['sambaAccount', 'other'],
            })
        d = o.addAutofiller(sambaAccount.Autofill_samba())

        def cb(dummy):
            client.assertNothingSent()

            o['gidNumber'] = ['1000']
            self.failUnless('primaryGroupID' in o)
            self.failUnlessEqual(o['primaryGroupID'], [str(2 * 1000 + 1001)])
            o['gidNumber'] = ['1001']
            self.failUnlessEqual(o['primaryGroupID'], [str(2 * 1001 + 1001)])
            o['gidNumber'] = ['1002']
            self.failUnlessEqual(o['primaryGroupID'], [str(2 * 1002 + 1001)])
            o['gidNumber'] = ['2000']
            self.failUnlessEqual(o['primaryGroupID'], [str(2 * 2000 + 1001)])
            o['gidNumber'] = ['3000']
            self.failUnlessEqual(o['primaryGroupID'], [str(2 * 3000 + 1001)])
            o['gidNumber'] = ['0']
            self.failUnlessEqual(o['primaryGroupID'], [str(2 * 0 + 1001)])
            o['gidNumber'] = ['16000']
            self.failUnlessEqual(o['primaryGroupID'], [str(2 * 16000 + 1001)])

        d.addCallback(cb)
        return d


class LDAPAutoFill_sambaSamAccount(unittest.TestCase):
    def testMustHaveObjectClass(self):
        """Test that Autofill_samba fails unless object is a sambaSamAccount."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['something', 'other'],
            })
        autoFiller = sambaSamAccount.Autofill_samba(domainSID='foo')
        d = o.addAutofiller(autoFiller)

        def eb(val):
            client.assertNothingSent()
            val.trap(sambaSamAccount.ObjectMissingObjectClassException)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def testDefaultSetting(self):
        """Test that fields get their default values."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['sambaSamAccount', 'other'],
            })
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID='foo'))

        def cb(dummy):
            client.assertNothingSent()

            self.failUnlessEqual(sets.Set(o.keys()), sets.Set([
                'objectClass',
                'sambaAcctFlags',
                'sambaLogoffTime',
                'sambaLogonTime',
                'sambaPwdCanChange',
                'sambaPwdLastSet',
                'sambaPwdMustChange',
                ]))

            self.failUnlessEqual(o['sambaAcctFlags'], ['[UX         ]'])
            self.failUnlessEqual(o['sambaPwdLastSet'], ['1'])
            self.failUnlessEqual(o['sambaLogonTime'], ['0'])
            self.failUnlessEqual(o['sambaLogoffTime'], ['0'])
            self.failUnlessEqual(o['sambaPwdCanChange'], ['0'])
            self.failUnlessEqual(o['sambaPwdMustChange'], ['0'])

        d.addCallback(cb)
        return d

    def testDefaultSetting_fixedPrimaryGroupSID(self):
        """Test that fields get their default values."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['sambaSamAccount', 'other'],
            })
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID='foo',
                                                           fixedPrimaryGroupSID=4131312))

        def cb(dummy):
            client.assertNothingSent()

            self.failUnlessEqual(sets.Set(o.keys()), sets.Set([
                'objectClass',
                'sambaAcctFlags',
                'sambaLogoffTime',
                'sambaLogonTime',
                'sambaPwdCanChange',
                'sambaPwdLastSet',
                'sambaPwdMustChange',
                'sambaPrimaryGroupSID',
                ]))

            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-4131312'])
            self.failUnlessEqual(o['sambaAcctFlags'], ['[UX         ]'])
            self.failUnlessEqual(o['sambaPwdLastSet'], ['1'])
            self.failUnlessEqual(o['sambaLogonTime'], ['0'])
            self.failUnlessEqual(o['sambaLogoffTime'], ['0'])
            self.failUnlessEqual(o['sambaPwdCanChange'], ['0'])
            self.failUnlessEqual(o['sambaPwdMustChange'], ['0'])

        d.addCallback(cb)
        return d

    def testSambaSID(self):
        """Test that sambaSID field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['sambaSamAccount', 'other'],
            })
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID='foo'))

        def cb(dummy):
            client.assertNothingSent()

            o['uidNumber'] = ['1000']
            self.failUnless('sambaSID' in o)
            self.failUnlessEqual(o['sambaSID'], ['foo-%s' % (2 * 1000 + 1000)])
            o['uidNumber'] = ['1001']
            self.failUnlessEqual(o['sambaSID'], ['foo-%s' % (2 * 1001 + 1000)])
            o['uidNumber'] = ['1002']
            self.failUnlessEqual(o['sambaSID'], ['foo-%s' % (2 * 1002 + 1000)])
            o['uidNumber'] = ['2000']
            self.failUnlessEqual(o['sambaSID'], ['foo-%s' % (2 * 2000 + 1000)])
            o['uidNumber'] = ['3000']
            self.failUnlessEqual(o['sambaSID'], ['foo-%s' % (2 * 3000 + 1000)])
            o['uidNumber'] = ['0']
            self.failUnlessEqual(o['sambaSID'], ['foo-%s' % (2 * 0 + 1000)])
            o['uidNumber'] = ['16000']
            self.failUnlessEqual(o['sambaSID'], ['foo-%s' % (2 * 16000 + 1000)])

        d.addCallback(cb)
        return d

    def testSambaSID_preExisting(self):
        """Test that sambaSID field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['sambaSamAccount', 'other'],
            'uidNumber': ['1000'],
            })
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID='foo'))

        def cb(dummy):
            client.assertNothingSent()

            self.failUnless('sambaSID' in o)
            self.failUnlessEqual(o['sambaSID'], ['foo-%s' % (2 * 1000 + 1000)])

        d.addCallback(cb)
        return d

    def testSambaPrimaryGroupSID(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                            dn='cn=foo,dc=example,dc=com',
                                            attributes={
            'objectClass': ['sambaSamAccount', 'other'],
            })
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID='foo'))

        def cb(dummy):
            client.assertNothingSent()

            o['gidNumber'] = ['1000']
            self.failUnless('sambaPrimaryGroupSID' in o)
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-%s' % (2 * 1000 + 1001)])
            o['gidNumber'] = ['1001']
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-%s' % (2 * 1001 + 1001)])
            o['gidNumber'] = ['1002']
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-%s' % (2 * 1002 + 1001)])
            o['gidNumber'] = ['2000']
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-%s' % (2 * 2000 + 1001)])
            o['gidNumber'] = ['3000']
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-%s' % (2 * 3000 + 1001)])
            o['gidNumber'] = ['0']
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-%s' % (2 * 0 + 1001)])
            o['gidNumber'] = ['16000']
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-%s' % (2 * 16000 + 1001)])

        d.addCallback(cb)
        return d

    def testSambaPrimaryGroupSID_preExisting(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                            dn='cn=foo,dc=example,dc=com',
                                            attributes={
            'objectClass': ['sambaSamAccount', 'other'],
            'gidNumber': ['1000'],
            })
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID='foo'))

        def cb(dummy):
            client.assertNothingSent()

            self.failUnless('sambaPrimaryGroupSID' in o)
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-%s' % (2 * 1000 + 1001)])

        d.addCallback(cb)
        return d

    def testSambaPrimaryGroupSID_notUpdatedWhenFixed(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                            dn='cn=foo,dc=example,dc=com',
                                            attributes={
            'objectClass': ['sambaSamAccount', 'other'],
            })
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID='foo',
                                                           fixedPrimaryGroupSID=4242))

        def cb(dummy):
            client.assertNothingSent()

            self.failUnless('sambaPrimaryGroupSID' in o)
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-4242'])
            o['gidNumber'] = ['1000']
            self.failUnless('sambaPrimaryGroupSID' in o)
            self.failUnlessEqual(o['sambaPrimaryGroupSID'], ['foo-4242'])

        d.addCallback(cb)
        return d
