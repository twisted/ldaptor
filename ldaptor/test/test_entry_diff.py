"""
Test cases for ldaptor.diff
"""

from twisted.trial import unittest
import sets
from ldaptor.protocols.ldap import ldifdelta, distinguishedname
from ldaptor import delta, entry

class TestDiffEntry(unittest.TestCase):
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
        self.assertEquals(result, None)

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
        self.assertEquals(result,
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
        self.assertEquals(result,
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
        self.assertEquals(result,
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
        self.assertEquals(result,
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
        self.assertEquals(result,
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
        self.assertEquals(result,
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
        self.assertEquals(result,
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
        self.assertEquals(result,
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
        self.assertEquals(result,
                          delta.ModifyOp('cn=Paula Jensen,ou=Product Development,dc=airius,dc=com',
                                         [
            delta.Add('postalAddress', ['123 Anystreet $ Sunnyvale, CA $ 94086']),
            delta.Delete('description', ['Something']),
            delta.Delete('facsimiletelephonenumber', ['+1 408 555 9876']),
            delta.Add('telephonenumber', ['+1 408 555 1234', '+1 408 555 5678']),
            delta.Delete('telephonenumber', ['+123 456']),
            ]))
