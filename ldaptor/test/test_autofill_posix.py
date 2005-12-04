"""
Test cases for ldaptor.protocols.ldap.autofill.posixAccount module.
"""

from twisted.trial import unittest
from ldaptor.protocols.ldap import ldapsyntax, autofill
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.autofill import posixAccount
from ldaptor.testutil import LDAPClientTestDriver
from twisted.trial.util import deferredResult, deferredError

class LDAPAutoFill_Posix(unittest.TestCase):
    def testMustHaveObjectClass(self):
        """Test that Autofill_posix fails unless object is a posixAccount."""
        client = LDAPClientTestDriver()
        o=ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['something', 'other'],
            })
        autoFiller = posixAccount.Autofill_posix(baseDN='dc=example,dc=com')
        d = o.addAutofiller(autoFiller)

        val = deferredError(d)
        client.assertNothingSent()

        val.trap(autofill.ObjectMissingObjectClassException)

    def testDefaultSetting(self):
        """Test that fields get their default values."""

        client = LDAPClientTestDriver(
            # uid==1000 -> free
            [   pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1000 -> taken
            [   pureldap.LDAPSearchResultEntry(objectName='',
                                           attributes=[('objectClass',
                                                        ('foo',
                                                         'posixAccount',
                                                         'bar'))]),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],
            # gid==1500 -> free
            [   pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1250 -> free
            [   pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1125 -> free
            [   pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1062 -> free
            [   pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],
            # gid==1031 -> free
            [   pureldap.LDAPSearchResultEntry(objectName='',
                                               attributes=[('objectClass',
                                                            ('foo',
                                                             'posixAccount',
                                                             'bar'))]),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1046 -> free
            [   pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1038 -> taken
            [   pureldap.LDAPSearchResultEntry(objectName='',
                                               attributes=[('objectClass',
                                                            ('foo',
                                                             'posixAccount',
                                                             'bar'))]),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1042 -> free
            [   pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1040 -> taken
            [   pureldap.LDAPSearchResultEntry(objectName='',
                                               attributes=[('objectClass',
                                                            ('foo',
                                                             'posixAccount',
                                                             'bar'))]),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],

            # gid==1041 -> taken
            [   pureldap.LDAPSearchResultEntry(objectName='',
                                               attributes=[('objectClass',
                                                            ('foo',
                                                             'posixAccount',
                                                             'bar'))]),
                pureldap.LDAPSearchResultDone(resultCode=0,
                                              matchedDN='',
                                              errorMessage=''),],
           )

        o=ldapsyntax.LDAPEntryWithAutoFill(client=client,
                                           dn='cn=foo,dc=example,dc=com',
                                           attributes={
            'objectClass': ['posixAccount', 'other'],
            })

        d = o.addAutofiller(posixAccount.Autofill_posix(baseDN='dc=example,dc=com'))
        val = deferredResult(d)

        client.assertSent(
            *[

            pureldap.LDAPSearchRequest(
            baseObject='dc=example,dc=com', scope=2,
            derefAliases=0, sizeLimit=1, timeLimit=0, typesOnly=0,
            filter=pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription(value='uidNumber'),
                                                     assertionValue=pureldap.LDAPAssertionValue(value='1000')),
            attributes=()),

            ] + [
            pureldap.LDAPSearchRequest(
            baseObject='dc=example,dc=com', scope=2,
            derefAliases=0, sizeLimit=1, timeLimit=0, typesOnly=0,
            filter=pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription(value='gidNumber'),
                                                     assertionValue=pureldap.LDAPAssertionValue(value=str(x))),
            attributes=())
            for x in (1000, 1500, 1250, 1125, 1062, 1031, 1046, 1038, 1042, 1040, 1041)])

        self.failUnless('loginShell' in o)
        self.failUnlessEqual(o['loginShell'], ['/bin/sh'])

        self.failUnless('uidNumber' in o)
        self.failUnlessEqual(o['uidNumber'], ['1000'])
        self.failUnless('gidNumber' in o)
        self.failUnlessEqual(o['gidNumber'], ['1042'])
