"""
Test cases for ldaptor.entry
"""

from twisted.trial import unittest

from ldaptor import delta, entry
from ldaptor.protocols.ldap.ldaperrors import LDAPInvalidCredentials



class TestBaseLDAPEntry(unittest.TestCase):
    """
    Tests for ldaptor.entry.BaseLDAPEntry.
    """

    def testEqualitySameType(self):
        """
        It is equal if it has the same DN (case insensitive)
        and same attributes and values.
        """
        a = entry.BaseLDAPEntry(
            dn='dc=foo',
            attributes={
                'foo': ['bar'],
            })
        b = entry.BaseLDAPEntry(
            dn='Dc=Foo',
            attributes={
                'foo': ['bar'],
            })

        self.assertEqual(a, b)

    def testEqualityDifferentType(self):
        """
        It is not equal with objects of different types.
        """
        a = entry.BaseLDAPEntry(dn='dc=foo', attributes={})
        self.assertFalse(a == object())

    def testInequalityDifferentDN(self):
        """
        Entries are not equal if their DNs are not equal
        """
        a = entry.BaseLDAPEntry(dn='dn=foo', attributes={'foo': ['bar']})
        b = entry.BaseLDAPEntry(dn='dn=bar', attributes={'foo': ['bar']})
        self.assertNotEqual(a, b)

    def testBindPlainText(self):
        """
        It will bind when the password for the entry is stored in plain text,
        and will return a deferred which has itself as callback.
        """
        sut = entry.BaseLDAPEntry(
            dn='dc=foo',
            attributes={
                'userPassword': [b'some-plain-text'],
            })

        deferred = sut.bind(b'some-plain-text')
        result = self.successResultOf(deferred)

        self.assertIs(sut, result)


    def testBindSeededSHA(self):
        """
        It can bind with password stored in seeded SHA.
        """
        sut = entry.BaseLDAPEntry(
            dn='dc=foo',
            attributes={
                'userPassword': [b'{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8='],
            })

        deferred = sut.bind(b'secret')
        result = self.successResultOf(deferred)

        self.assertIs(sut, result)


    def testBindPlainTextError(self):
        """
        Return a LDAPInvalidCredentials failure when password don't match.
        """
        sut = entry.BaseLDAPEntry(
            dn='dc=foo',
            attributes={
                'userPassword': [b'some-plain-text'],
            })

        deferred = sut.bind(b'other-password')
        failure = self.failureResultOf(deferred)

        self.assertTrue(failure.check(LDAPInvalidCredentials))



    def testBindSHAError(self):
        """
        Return a LDAPInvalidCredentials failure when encoded password don't
        match.
        """
        sut = entry.BaseLDAPEntry(
            dn='dc=foo',
            attributes={
                'userPassword': [b'{SSHA}anythinghere'],
            })

        deferred = sut.bind(b'other-password')
        failure = self.failureResultOf(deferred)

        self.assertTrue(failure.check(LDAPInvalidCredentials))

    def testGetLDIF(self):
        """
        Getting human readable representation of an entry
        """
        sut = entry.BaseLDAPEntry(
            dn='dc=foo',
            attributes={
                'foo': ['bar'],
                'bar': ['foo'],
            }
        )
        self.assertEqual(sut.getLDIF(), u'dn: dc=foo\nbar: foo\nfoo: bar\n\n')

    def testNonzero(self):
        """Entry is always non-zero"""
        sut = entry.BaseLDAPEntry(dn='')
        self.assertTrue(bool(sut))

    def testRepr(self):
        """
        Getting string representation of an entry
        """
        sut = entry.BaseLDAPEntry(
            dn='dc=foo',
            attributes={
                'foo': ['bar'],
                'bar': ['foo'],
            }
        )
        self.assertEqual(repr(sut), "BaseLDAPEntry('dc=foo', {'bar': ['foo'], 'foo': ['bar']})")



class TestDiffEntry(unittest.TestCase):
    """
    Tests for ldaptor.entry.BaseLDAPEntry.diff()
    """
    def testEqual(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            })
        result = a.diff(b)
        self.assertEqual(result, None)

    def testAdd_New_OneType_OneValue(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            'baz': ['quux'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('dc=foo',
                                         [
            delta.Add('baz', ['quux']),
            ]))

    def testAdd_New_OneType_ManyValues(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            'baz': ['quux', 'thud', 'foo'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('dc=foo',
                                         [
            delta.Add('baz', ['quux', 'thud', 'foo']),
            ]))

    def testAdd_New_ManyTypes(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            'baz': ['quux'],
            'bang': ['thud'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('dc=foo',
                                         [
            delta.Add('bang', ['thud']),
            delta.Add('baz', ['quux']),
            ]))

    def testAdd_Existing_OneType_OneValue(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar', 'quux'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('dc=foo',
                                         [
            delta.Add('foo', ['quux']),
            ]))

    def testAdd_Existing_OneType_ManyValues(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar', 'quux', 'thud', 'foo'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('dc=foo',
                                         [
            delta.Add('foo', ['quux', 'thud', 'foo']),
            ]))

    def testAdd_NewAndExisting_ManyTypes(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            'baz': ['quux'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar', 'thud', 'bang'],
            'baz': ['quux', 'bar', 'stump'],
            'bang': ['thud', 'barble'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('dc=foo',
                                         [
            delta.Add('bang', ['thud', 'barble']),
            delta.Add('baz', ['bar', 'stump']),
            delta.Add('foo', ['thud', 'bang']),
            ]))

    def testDelete_All_OneType(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            'baz': ['quux', 'thud'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('dc=foo',
                                         [
            delta.Delete('baz', ['quux', 'thud']),
            ]))

    def testDelete_Some_OneType(self):
        a = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            'baz': ['quux', 'thud'],
            })
        b = entry.BaseLDAPEntry(dn='dc=foo',
                                attributes={
            'foo': ['bar'],
            'baz': ['thud'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('dc=foo',
                                         [
            delta.Delete('baz', ['quux']),
            ]))

    def testComplex(self):
        a = entry.BaseLDAPEntry(dn='cn=Paula Jensen,ou=Product Development,dc=airius,dc=com',
                                attributes={
            'description': ['Something'],
            'telephonenumber': ['+123 456'],
            'facsimiletelephonenumber': ['+1 408 555 9876'],
            })
        b = entry.BaseLDAPEntry(dn='cn=Paula Jensen,ou=Product Development,dc=airius,dc=com',
                                attributes={
            'postalAddress': ['123 Anystreet $ Sunnyvale, CA $ 94086'],
            'telephonenumber': ['+1 408 555 1234', '+1 408 555 5678'],
            })
        result = a.diff(b)
        self.assertEqual(result,
                          delta.ModifyOp('cn=Paula Jensen,ou=Product Development,dc=airius,dc=com',
                                         [
            delta.Add('postalAddress', ['123 Anystreet $ Sunnyvale, CA $ 94086']),
            delta.Delete('description', ['Something']),
            delta.Delete('facsimiletelephonenumber', ['+1 408 555 9876']),
            delta.Add('telephonenumber', ['+1 408 555 1234', '+1 408 555 5678']),
            delta.Delete('telephonenumber', ['+123 456']),
            ]))
