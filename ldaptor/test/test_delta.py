"""
Test cases for ldaptor.protocols.ldap.delta
"""

from twisted.trial import unittest, util
from ldaptor import delta, entry, attributeset, inmemory
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname, ldaperrors

class TestModifications(unittest.TestCase):
    def setUp(self):
        self.foo = ldapsyntax.LDAPEntry(
            None,
            dn='cn=foo,dc=example,dc=com',
            attributes={
            'objectClass': ['person'],
            'cn': ['foo', 'thud'],
            'sn': ['bar'],
            'more': ['junk'],
            })

    def testAddOld(self):
        mod = delta.Add('cn', ['quux'])
        mod.patch(self.foo)

	self.failIf('stuff' in self.foo)
	self.failUnlessEqual(self.foo['cn'], ['foo', 'thud', 'quux'])

    def testAddNew(self):
        mod = delta.Add('stuff', ['val1', 'val2'])
        mod.patch(self.foo)

	self.failUnlessEqual(self.foo['stuff'], ['val1', 'val2'])
	self.failUnlessEqual(self.foo['cn'], ['foo', 'thud'])

    def testDelete(self):
        mod = delta.Delete('cn', ['thud'])
        mod.patch(self.foo)

        self.failIf('stuff' in self.foo)
	self.failUnlessEqual(self.foo['cn'], ['foo'])

    def testDeleteAll(self):
        mod = delta.Delete('more')
        mod.patch(self.foo)

        self.failIf('stuff' in self.foo)
	self.failUnlessEqual(self.foo['cn'], ['foo', 'thud'])

    def testDelete_FailOnNonExistingAttributeType_All(self):
        mod = delta.Delete('notexist', [])
        self.assertRaises(KeyError,
                          mod.patch,
                          self.foo)

    def testDelete_FailOnNonExistingAttributeType_OneValue(self):
        mod = delta.Delete('notexist', ['a'])
        self.assertRaises(KeyError,
                          mod.patch,
                          self.foo)

    def testDelete_FailOnNonExistingAttributeValue(self):
        mod = delta.Delete('cn', ['notexist'])
        self.assertRaises(LookupError,
                          mod.patch,
                          self.foo)


    def testReplace_Add(self):
        mod = delta.Replace('stuff', ['val1', 'val2'])
        mod.patch(self.foo)

	self.failUnlessEqual(self.foo['stuff'], ['val1', 'val2'])
	self.failUnlessEqual(self.foo['sn'], ['bar'])
	self.failUnlessEqual(self.foo['more'], ['junk'])

    def testReplace_Modify(self):
        mod = delta.Replace('sn', ['baz'])
        mod.patch(self.foo)

	self.failIf('stuff' in self.foo)
	self.failUnlessEqual(self.foo['sn'], ['baz'])
	self.failUnlessEqual(self.foo['more'], ['junk'])

    def testReplace_Delete_Existing(self):
        mod = delta.Replace('more', [])
        mod.patch(self.foo)

	self.failIf('stuff' in self.foo)
	self.failUnlessEqual(self.foo['sn'], ['bar'])
	self.failIf('more' in self.foo)

    def testReplace_Delete_NonExisting(self):
        mod = delta.Replace('nonExisting', [])
        mod.patch(self.foo)

	self.failIf('stuff' in self.foo)
	self.failUnlessEqual(self.foo['sn'], ['bar'])
	self.failUnlessEqual(self.foo['more'], ['junk'])

class TestModificationOpLDIF(unittest.TestCase):
    def testAdd(self):
        m=delta.Add('foo', ['bar', 'baz'])
        self.assertEquals(m.asLDIF(),
                          """\
add: foo
foo: bar
foo: baz
-
""")

    def testDelete(self):
        m=delta.Delete('foo', ['bar', 'baz'])
        self.assertEquals(m.asLDIF(),
                          """\
delete: foo
foo: bar
foo: baz
-
""")

    def testDeleteAll(self):
        m=delta.Delete('foo')
        self.assertEquals(m.asLDIF(),
                          """\
delete: foo
-
""")

    def testReplace(self):
        m=delta.Replace('foo', ['bar', 'baz'])
        self.assertEquals(m.asLDIF(),
                          """\
replace: foo
foo: bar
foo: baz
-
""")

    def testReplaceAll(self):
        m=delta.Replace('thud')
        self.assertEquals(m.asLDIF(),
                          """\
replace: thud
-
""")


class TestAddOpLDIF(unittest.TestCase):
    def testSimple(self):
        op=delta.AddOp(entry.BaseLDAPEntry(
            dn='dc=example,dc=com',
            attributes={'foo': ['bar', 'baz'],
                        'quux': ['thud']}))
        self.assertEquals(op.asLDIF(),
                          """\
dn: dc=example,dc=com
changetype: add
foo: bar
foo: baz
quux: thud

""")


class TestDeleteOpLDIF(unittest.TestCase):
    def testSimple(self):
        op=delta.DeleteOp('dc=example,dc=com')
        self.assertEquals(op.asLDIF(),
                          """\
dn: dc=example,dc=com
changetype: delete

""")



class TestOperationLDIF(unittest.TestCase):
    def testModify(self):
        op=delta.ModifyOp('cn=Paula Jensen, ou=Product Development, dc=airius, dc=com',
                          [
            delta.Add('postaladdress',
                      ['123 Anystreet $ Sunnyvale, CA $ 94086']),
            delta.Delete('description'),
            delta.Replace('telephonenumber', ['+1 408 555 1234', '+1 408 555 5678']),
            delta.Delete('facsimiletelephonenumber', ['+1 408 555 9876']),
            ])
        self.assertEquals(op.asLDIF(),
                          """\
dn: cn=Paula Jensen,ou=Product Development,dc=airius,dc=com
changetype: modify
add: postaladdress
postaladdress: 123 Anystreet $ Sunnyvale, CA $ 94086
-
delete: description
-
replace: telephonenumber
telephonenumber: +1 408 555 1234
telephonenumber: +1 408 555 5678
-
delete: facsimiletelephonenumber
facsimiletelephonenumber: +1 408 555 9876
-

""")

class TestModificationComparison(unittest.TestCase):
    def testEquality_Add_True(self):
        a = delta.Add('k', ['b', 'c', 'd'])
        b = delta.Add('k', ['b', 'c', 'd'])
        self.assertEquals(a, b)

    def testEquality_AddVsDelete_False(self):
        a = delta.Add('k', ['b', 'c', 'd'])
        b = delta.Delete('k', ['b', 'c', 'd'])
        self.assertNotEquals(a, b)

    def testEquality_AttributeSet_False(self):
        a = delta.Add('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        self.assertNotEquals(a, b)

    def testEquality_List_False(self):
        a = delta.Add('k', ['b', 'c', 'd'])
        b = ['b', 'c', 'd']
        self.assertNotEquals(a, b)

class TestOperations(unittest.TestCase):
    def setUp(self):
        self.root = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))
        self.meta=self.root.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('ou=metasyntactic'),
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['metasyntactic'],
            })
        self.foo=self.meta.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('cn=foo'),
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['foo'],
            })
        self.bar=self.meta.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('cn=bar'),
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['bar'],
            })

        self.empty=self.root.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('ou=empty'),
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['empty'],
            })

        self.oneChild=self.root.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('ou=oneChild'),
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['oneChild'],
            })
        self.theChild=self.oneChild.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('cn=theChild'),
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['theChild'],
            })

    def testAddOp_DNExists(self):
        foo2 = entry.BaseLDAPEntry(
            dn='cn=foo,ou=metasyntactic,dc=example,dc=com',
            attributes={'foo': ['bar', 'baz'],
                        'quux': ['thud']})
        op = delta.AddOp(foo2)
        d = op.patch(self.root)
        self.assertRaises(ldaperrors.LDAPEntryAlreadyExists,
                          util.wait, d)

    def testDeleteOp_DNNotFound(self):
        op = delta.DeleteOp('cn=nope,dc=example,dc=com')
        d = op.patch(self.root)
        self.assertRaises(ldaperrors.LDAPNoSuchObject,
                          util.wait, d)

    def testModifyOp_DNNotFound(self):
        op = delta.ModifyOp('cn=nope,dc=example,dc=com',
                            [delta.Add('foo', ['bar'])])
        d = op.patch(self.root)
        self.assertRaises(ldaperrors.LDAPNoSuchObject,
                          util.wait, d)
