"""
Test cases for ldaptor.protocols.ldap.autofill.sambaAccount module.
"""
from twisted.trial import unittest

from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.protocols.ldap.autofill import sambaAccount, sambaSamAccount
from ldaptor import testutil


class LDAPAutoFill_sambaAccount(unittest.TestCase):
    def testMustHaveObjectClass(self):
        """Test that Autofill_samba fails unless object is a sambaAccount."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["something", "other"],
            },
        )
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
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaAccount", "other"],
            },
        )
        d = o.addAutofiller(sambaAccount.Autofill_samba())

        def cb(dummy):
            client.assertNothingSent()

            self.assertTrue("acctFlags" in o)
            self.assertEqual(o["acctFlags"], ["[UX         ]"])

            self.assertTrue("pwdLastSet" in o)
            self.assertEqual(o["pwdLastSet"], ["0"])
            self.assertTrue("logonTime" in o)
            self.assertEqual(o["logonTime"], ["0"])
            self.assertTrue("logoffTime" in o)
            self.assertEqual(o["logoffTime"], ["0"])
            self.assertTrue("pwdCanChange" in o)
            self.assertEqual(o["pwdCanChange"], ["0"])
            self.assertTrue("pwdMustChange" in o)
            self.assertEqual(o["pwdMustChange"], ["0"])

        d.addCallback(cb)
        return d

    def testRid(self):
        """Test that rid field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaAccount", "other"],
            },
        )
        d = o.addAutofiller(sambaAccount.Autofill_samba())

        def cb(dummy):
            client.assertNothingSent()

            o["uidNumber"] = ["1000"]
            self.assertTrue("rid" in o)
            self.assertEqual(o["rid"], [str(2 * 1000 + 1000)])
            o["uidNumber"] = ["1001"]
            self.assertEqual(o["rid"], [str(2 * 1001 + 1000)])
            o["uidNumber"] = ["1002"]
            self.assertEqual(o["rid"], [str(2 * 1002 + 1000)])
            o["uidNumber"] = ["2000"]
            self.assertEqual(o["rid"], [str(2 * 2000 + 1000)])
            o["uidNumber"] = ["3000"]
            self.assertEqual(o["rid"], [str(2 * 3000 + 1000)])
            o["uidNumber"] = ["0"]
            self.assertEqual(o["rid"], [str(2 * 0 + 1000)])
            o["uidNumber"] = ["16000"]
            self.assertEqual(o["rid"], [str(2 * 16000 + 1000)])

        d.addCallback(cb)
        return d

    def testPrimaryGroupId(self):
        """Test that primaryGroupID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaAccount", "other"],
            },
        )
        d = o.addAutofiller(sambaAccount.Autofill_samba())

        def cb(dummy):
            client.assertNothingSent()

            o["gidNumber"] = ["1000"]
            self.assertTrue("primaryGroupID" in o)
            self.assertEqual(o["primaryGroupID"], [str(2 * 1000 + 1001)])
            o["gidNumber"] = ["1001"]
            self.assertEqual(o["primaryGroupID"], [str(2 * 1001 + 1001)])
            o["gidNumber"] = ["1002"]
            self.assertEqual(o["primaryGroupID"], [str(2 * 1002 + 1001)])
            o["gidNumber"] = ["2000"]
            self.assertEqual(o["primaryGroupID"], [str(2 * 2000 + 1001)])
            o["gidNumber"] = ["3000"]
            self.assertEqual(o["primaryGroupID"], [str(2 * 3000 + 1001)])
            o["gidNumber"] = ["0"]
            self.assertEqual(o["primaryGroupID"], [str(2 * 0 + 1001)])
            o["gidNumber"] = ["16000"]
            self.assertEqual(o["primaryGroupID"], [str(2 * 16000 + 1001)])

        d.addCallback(cb)
        return d


class LDAPAutoFill_sambaSamAccount(unittest.TestCase):
    def testMustHaveObjectClass(self):
        """Test that Autofill_samba fails unless object is a sambaSamAccount."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["something", "other"],
            },
        )
        autoFiller = sambaSamAccount.Autofill_samba(domainSID="foo")
        d = o.addAutofiller(autoFiller)

        def eb(val):
            client.assertNothingSent()
            val.trap(sambaSamAccount.ObjectMissingObjectClassException)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def testDefaultSetting(self):
        """Test that fields get their default values."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))

        def cb(dummy):
            client.assertNothingSent()

            self.assertEqual(
                set(o.keys()),
                {
                    "objectClass",
                    "sambaAcctFlags",
                    "sambaLogoffTime",
                    "sambaLogonTime",
                    "sambaPwdCanChange",
                    "sambaPwdLastSet",
                    "sambaPwdMustChange",
                },
            )

            self.assertEqual(o["sambaAcctFlags"], ["[UX         ]"])
            self.assertEqual(o["sambaPwdLastSet"], ["1"])
            self.assertEqual(o["sambaLogonTime"], ["0"])
            self.assertEqual(o["sambaLogoffTime"], ["0"])
            self.assertEqual(o["sambaPwdCanChange"], ["0"])
            self.assertEqual(o["sambaPwdMustChange"], ["0"])

        d.addCallback(cb)
        return d

    def testDefaultSetting_fixedPrimaryGroupSID(self):
        """Test that fields get their default values."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )
        d = o.addAutofiller(
            sambaSamAccount.Autofill_samba(
                domainSID="foo", fixedPrimaryGroupSID=4131312
            )
        )

        def cb(dummy):
            client.assertNothingSent()

            self.assertEqual(
                set(o.keys()),
                {
                    "objectClass",
                    "sambaAcctFlags",
                    "sambaLogoffTime",
                    "sambaLogonTime",
                    "sambaPwdCanChange",
                    "sambaPwdLastSet",
                    "sambaPwdMustChange",
                    "sambaPrimaryGroupSID",
                },
            )

            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-4131312"])
            self.assertEqual(o["sambaAcctFlags"], ["[UX         ]"])
            self.assertEqual(o["sambaPwdLastSet"], ["1"])
            self.assertEqual(o["sambaLogonTime"], ["0"])
            self.assertEqual(o["sambaLogoffTime"], ["0"])
            self.assertEqual(o["sambaPwdCanChange"], ["0"])
            self.assertEqual(o["sambaPwdMustChange"], ["0"])

        d.addCallback(cb)
        return d

    def testSambaSID(self):
        """Test that sambaSID field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))

        def cb(dummy):
            client.assertNothingSent()

            o["uidNumber"] = ["1000"]
            self.assertTrue("sambaSID" in o)
            self.assertEqual(o["sambaSID"], ["foo-%s" % (2 * 1000 + 1000)])
            o["uidNumber"] = ["1001"]
            self.assertEqual(o["sambaSID"], ["foo-%s" % (2 * 1001 + 1000)])
            o["uidNumber"] = ["1002"]
            self.assertEqual(o["sambaSID"], ["foo-%s" % (2 * 1002 + 1000)])
            o["uidNumber"] = ["2000"]
            self.assertEqual(o["sambaSID"], ["foo-%s" % (2 * 2000 + 1000)])
            o["uidNumber"] = ["3000"]
            self.assertEqual(o["sambaSID"], ["foo-%s" % (2 * 3000 + 1000)])
            o["uidNumber"] = ["0"]
            self.assertEqual(o["sambaSID"], ["foo-%s" % (2 * 0 + 1000)])
            o["uidNumber"] = ["16000"]
            self.assertEqual(o["sambaSID"], ["foo-%s" % (2 * 16000 + 1000)])

        d.addCallback(cb)
        return d

    def testSambaSID_preExisting(self):
        """Test that sambaSID field is updated based on uidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
                "uidNumber": ["1000"],
            },
        )
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))

        def cb(dummy):
            client.assertNothingSent()

            self.assertTrue("sambaSID" in o)
            self.assertEqual(o["sambaSID"], ["foo-%s" % (2 * 1000 + 1000)])

        d.addCallback(cb)
        return d

    def testSambaPrimaryGroupSID(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))

        def cb(dummy):
            client.assertNothingSent()

            o["gidNumber"] = ["1000"]
            self.assertTrue("sambaPrimaryGroupSID" in o)
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-%s" % (2 * 1000 + 1001)])
            o["gidNumber"] = ["1001"]
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-%s" % (2 * 1001 + 1001)])
            o["gidNumber"] = ["1002"]
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-%s" % (2 * 1002 + 1001)])
            o["gidNumber"] = ["2000"]
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-%s" % (2 * 2000 + 1001)])
            o["gidNumber"] = ["3000"]
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-%s" % (2 * 3000 + 1001)])
            o["gidNumber"] = ["0"]
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-%s" % (2 * 0 + 1001)])
            o["gidNumber"] = ["16000"]
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-%s" % (2 * 16000 + 1001)])

        d.addCallback(cb)
        return d

    def testSambaPrimaryGroupSID_preExisting(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
                "gidNumber": ["1000"],
            },
        )
        d = o.addAutofiller(sambaSamAccount.Autofill_samba(domainSID="foo"))

        def cb(dummy):
            client.assertNothingSent()

            self.assertTrue("sambaPrimaryGroupSID" in o)
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-%s" % (2 * 1000 + 1001)])

        d.addCallback(cb)
        return d

    def testSambaPrimaryGroupSID_notUpdatedWhenFixed(self):
        """Test that sambaPrimaryGroupSID field is updated based on gidNumber."""
        client = testutil.LDAPClientTestDriver()
        o = ldapsyntax.LDAPEntryWithAutoFill(
            client=client,
            dn="cn=foo,dc=example,dc=com",
            attributes={
                "objectClass": ["sambaSamAccount", "other"],
            },
        )
        d = o.addAutofiller(
            sambaSamAccount.Autofill_samba(domainSID="foo", fixedPrimaryGroupSID=4242)
        )

        def cb(dummy):
            client.assertNothingSent()

            self.assertTrue("sambaPrimaryGroupSID" in o)
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-4242"])
            o["gidNumber"] = ["1000"]
            self.assertTrue("sambaPrimaryGroupSID" in o)
            self.assertEqual(o["sambaPrimaryGroupSID"], ["foo-4242"])

        d.addCallback(cb)
        return d
