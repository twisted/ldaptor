"""
Test cases for ldaptor.protocols.ldap.ldif module.
"""

from twisted.trial import unittest
from ldaptor.protocols.ldap import ldifprotocol
from ldaptor.testutil import LDAPClientTestDriver

class TestLDIFParsing(unittest.TestCase):
    class LDIFDriver(ldifprotocol.LDIF):
        def __init__(self):
            self.listOfCompleted = []
        def completed(self, obj):
            self.listOfCompleted.append(obj)

    def testFromLDIF(self):
        client = LDAPClientTestDriver()
        proto = self.LDIFDriver()
        for line in (

            "dn: cn=foo,dc=example,dc=com",
            "objectClass: a",
            "objectClass: b",
            "aValue: a",
            "aValue: b",
            "bValue: c",
            "",

            "dn: cn=bar,dc=example,dc=com",
            "objectClass: c",
            "aValue:: IEZPTyE=",
            "aValue: b",
            "bValue: C",
            "",

            ):
            proto.lineReceived(line)

        self.failUnlessEqual(len(proto.listOfCompleted), 2)

        o = proto.listOfCompleted.pop(0)
        self.failUnlessEqual(str(o.dn), 'cn=foo,dc=example,dc=com')
	self.failUnlessEqual(o['objectClass'], ['a', 'b'])
	self.failUnlessEqual(o['aValue'], ['a', 'b'])
	self.failUnlessEqual(o['bValue'], ['c'])

        o = proto.listOfCompleted.pop(0)
        self.failUnlessEqual(str(o.dn), 'cn=bar,dc=example,dc=com')
	self.failUnlessEqual(o['objectClass'], ['c'])
	self.failUnlessEqual(o['aValue'], [' FOO!', 'b'])
	self.failUnlessEqual(o['bValue'], ['C'])
        client.assertNothingSent()

        self.failUnlessEqual(proto.listOfCompleted, [])

        client.assertNothingSent()
