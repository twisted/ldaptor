"""
Test cases for ldaptor.protocols.ldap.delta
"""

from twisted.trial import unittest
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
        self.assertEqual(m.asLDIF(),
                         b"""\
add: foo
foo: bar
foo: baz
-
""")

    def testDelete(self):
        m=delta.Delete('foo', ['bar', 'baz'])
        self.assertEqual(m.asLDIF(),
                         b"""\
delete: foo
foo: bar
foo: baz
-
""")

    def testDeleteAll(self):
        m=delta.Delete('foo')
        self.assertEqual(m.asLDIF(),
                         b"""\
delete: foo
-
""")

    def testReplace(self):
        m=delta.Replace('foo', ['bar', 'baz'])
        self.assertEqual(m.asLDIF(),
                         b"""\
replace: foo
foo: bar
foo: baz
-
""")

    def testReplaceAll(self):
        m=delta.Replace('thud')
        self.assertEqual(m.asLDIF(),
                         b"""\
replace: thud
-
""")

    def testAddBase64(self):
        """
        LDIF attribute representation is base64 encoded
        if attribute value contains nonprintable characters
        or starts with reserved characters
        """
        m = delta.Add('attr', [':value1', 'value\n\r2'])
        self.assertEqual(m.asLDIF(),
                         b"""\
add: attr
attr:: OnZhbHVlMQ==
attr:: dmFsdWUKDTI=
-
""")


class OperationTestCase(unittest.TestCase):
    """
    Test case for operations on a LDAP tree.
    """
    def getRoot(self):
        """
        Returns a new LDAP root for dc=example,dc=com.
        """
        return inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))


class TestAddOpLDIF(OperationTestCase):
    """
    Unit tests for `AddOp`.
    """
    def testAsLDIF(self):
        """
        It will return the LDIF representation of the operation.
        """
        sut =delta.AddOp(entry.BaseLDAPEntry(
            dn='dc=example,dc=com',
            attributes={
                'foo': ['bar', 'baz'],
                'quux': ['thud'],
                },
            ))

        result = sut.asLDIF()

        self.assertEqual(b"""dn: dc=example,dc=com
changetype: add
foo: bar
foo: baz
quux: thud

""",
        result)

    def testAddOpEqualitySameEntry(self):
        """
        Objects are equal when the have the same LDAP entry.
        """
        first_entry = entry.BaseLDAPEntry(
            dn='ou=Duplicate Team, dc=example,dc=com',
            attributes={'foo': ['same', 'attributes']})
        second_entry = entry.BaseLDAPEntry(
            dn='ou=Duplicate Team, dc=example,dc=com',
            attributes={'foo': ['same', 'attributes']})

        first = delta.AddOp(first_entry)
        second = delta.AddOp(second_entry)

        self.assertEqual(first, second)

    def testAddOpInequalityDifferentEntry(self):
        """
        Objects are not equal when the have different LDAP entries.
        """
        first_entry = entry.BaseLDAPEntry(
            dn='ou=First Team, dc=example,dc=com',
            attributes={'foo': ['same', 'attributes']})
        second_entry = entry.BaseLDAPEntry(
            dn='ou=First Team, dc=example,dc=com',
            attributes={'foo': ['other', 'attributes']})

        first = delta.AddOp(first_entry)
        second = delta.AddOp(second_entry)

        self.assertNotEqual(first, second)

    def testAddOpInequalityNoEntryObject(self):
        """
        Objects is not equal with random objects.
        """
        team_entry = entry.BaseLDAPEntry(
            dn='ou=Duplicate Team, dc=example,dc=com',
            attributes={'foo': ['same', 'attributes']})
        sut = delta.AddOp(team_entry)

        self.assertNotEqual(sut, {'foo': ['same', 'attributes']})

    def testAddOpHashSimilar(self):
        """
        Objects which are equal have the same hash.
        """
        first_entry = entry.BaseLDAPEntry(
            dn='ou=Duplicate Team, dc=example,dc=com',
            attributes={'foo': ['same', 'attributes']})
        second_entry = entry.BaseLDAPEntry(
            dn='ou=Duplicate Team, dc=example,dc=com',
            attributes={'foo': ['same', 'attributes']})

        first = delta.AddOp(first_entry)
        second = delta.AddOp(second_entry)

        self.assertEqual(hash(first), hash(second))

    def testAddOpHashDifferent(self):
        """
        Objects which are not equal have different hash.
        """
        first_entry = entry.BaseLDAPEntry(
            dn='ou=Duplicate Team, dc=example,dc=com',
            attributes={'foo': ['one', 'attributes']})
        second_entry = entry.BaseLDAPEntry(
            dn='ou=Duplicate Team, dc=example,dc=com',
            attributes={'foo': ['other', 'attributes']})

        first = delta.AddOp(first_entry)
        second = delta.AddOp(second_entry)

        self.assertNotEqual(hash(first), hash(second))

    def testAddOp_DNExists(self):
        """
        It fails to perform the `add` operation for an existing entry.
        """
        root = self.getRoot()
        root.addChild(
            rdn='ou=Existing Team',
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['HR'],
            })

        hr_entry = entry.BaseLDAPEntry(
            dn='ou=Existing Team, dc=example,dc=com',
            attributes={'foo': ['dont', 'care']})
        sut = delta.AddOp(hr_entry)

        deferred = sut.patch(root)

        failure = self.failureResultOf(deferred)
        self.assertIsInstance(failure.value, ldaperrors.LDAPEntryAlreadyExists)


class TestDeleteOpLDIF(OperationTestCase):
    """
    Unit tests for DeleteOp.
    """
    def testAsLDIF(self):
        """
        It return the LDIF representation of the delete operation.
        """
        sut = delta.DeleteOp('dc=example,dc=com')

        result = sut.asLDIF()
        self.assertEqual(b"""dn: dc=example,dc=com
changetype: delete

""",
        result)

    def testDeleteOpEqualitySameDN(self):
        """
        Objects are equal when the have the same DN.
        """
        first_entry = entry.BaseLDAPEntry(dn='ou=Team, dc=example,dc=com')
        second_entry = entry.BaseLDAPEntry(dn='ou=Team, dc=example,dc=com')

        first = delta.DeleteOp(first_entry)
        second = delta.DeleteOp(second_entry)

        self.assertEqual(first, second)

    def testDeleteOpInequalityDifferentEntry(self):
        """
        DeleteOp objects are not equal when the have different LDAP entries.
        """
        first_entry = entry.BaseLDAPEntry(dn='ou=Team, dc=example,dc=com')
        second_entry = entry.BaseLDAPEntry(dn='ou=Cowboys, dc=example,dc=com')

        first = delta.DeleteOp(first_entry)
        second = delta.DeleteOp(second_entry)

        self.assertNotEqual(first, second)

    def testDeleteOpInequalityNoEntryObject(self):
        """
        DeleteOp objects is not equal with random objects.
        """
        team_entry = entry.BaseLDAPEntry(dn='ou=Team, dc=example,dc=com')

        sut = delta.DeleteOp(team_entry)

        self.assertNotEqual(sut, 'ou=Team, dc=example,dc=com')

    def testDeleteOpHashSimilar(self):
        """
        Objects which are equal have the same hash.
        """
        first_entry = entry.BaseLDAPEntry(dn='ou=Team, dc=example,dc=com')
        second_entry = entry.BaseLDAPEntry(dn='ou=Team, dc=example,dc=com')

        first = delta.DeleteOp(first_entry)
        second = delta.DeleteOp(second_entry)

        self.assertEqual(hash(first), hash(second))

    def testDeleteOpHashDifferent(self):
        """
        Objects which are not equal have different hash.
        """
        first_entry = entry.BaseLDAPEntry(dn='ou=Team, dc=example,dc=com')
        second_entry = entry.BaseLDAPEntry(dn='ou=Cowboys, dc=example,dc=com')

        first = delta.DeleteOp(first_entry)
        second = delta.DeleteOp(second_entry)

        self.assertNotEqual(hash(first), hash(second))

    def testDeleteOp_DNNotFound(self):
        """
        If fail to delete when the RDN does not exists.
        """
        root = self.getRoot()
        sut = delta.DeleteOp('cn=nope,dc=example,dc=com')

        deferred = sut.patch(root)

        failure = self.failureResultOf(deferred)
        self.assertIsInstance(failure.value, ldaperrors.LDAPNoSuchObject)


class TestModifyOp(OperationTestCase):
    """
    Unit tests for ModifyOp.
    """

    def testAsLDIF(self):
        """
        It will return a LDIF representation of the contained operations.
        """
        sut = delta.ModifyOp(
            'cn=Paula Jensen, ou=Dev Ops, dc=airius, dc=com',
            [
                delta.Add(
                    'postaladdress',
                    ['123 Anystreet $ Sunnyvale, CA $ 94086'],
                    ),
                delta.Delete('description'),
                delta.Replace(
                    'telephonenumber',
                    ['+1 408 555 1234', '+1 408 555 5678'],
                    ),
                delta.Delete(
                    'facsimiletelephonenumber', ['+1 408 555 9876']),
                ]
            )

        result = sut.asLDIF()

        self.assertEqual(b"""dn: cn=Paula Jensen,ou=Dev Ops,dc=airius,dc=com
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

""",
        result,
        )

    def testInequalityDiffertnDN(self):
        """
        Modify operations for different DN are not equal.
        """
        first = delta.ModifyOp(
            'cn=john,dc=example,dc=com',
            [delta.Delete('description')]
            )

        second = delta.ModifyOp(
            'cn=doe,dc=example,dc=com',
            [delta.Delete('description')]
            )

        self.assertNotEqual(first, second)

    def testInequalityNotModifyOP(self):
        """
        Modify operations are not equal with other object types.
        """
        sut = delta.ModifyOp(
            'cn=john,dc=example,dc=com',
            [delta.Delete('description')]
            )

        self.assertNotEqual('cn=john,dc=example,dc=com', sut)

    def testInequalityDiffertnOperations(self):
        """
        Modify operations for same DN but different operations are not equal.
        """
        first = delta.ModifyOp(
            'cn=john,dc=example,dc=com',
            [delta.Delete('description')]
            )
        second = delta.ModifyOp(
            'cn=doe,dc=example,dc=com',
            [delta.Delete('homeDirectory')]
            )

        self.assertNotEqual(first, second)

    def testHashEquality(self):
        """
        Modify operations can be hashed and equal objects have the same
        hash.
        """
        first = delta.ModifyOp(
            'cn=john,dc=example,dc=com',
            [delta.Delete('description')]
            )

        second = delta.ModifyOp(
            'cn=john,dc=example,dc=com',
            [delta.Delete('description')]
            )

        self.assertEqual(first, second)
        self.assertEqual(
            first.asLDIF(), second.asLDIF(),
            'LDIF equality is a precondition for valid hash values',
            )
        self.assertEqual(hash(first), hash(second))

    def testHashInequality(self):
        """
        Different modify operations have different hash values.
        """
        first = delta.ModifyOp(
            'cn=john,dc=example,dc=com',
            [delta.Delete('description')]
            )

        second = delta.ModifyOp(
            'cn=john,dc=example,dc=com',
            [delta.Delete('homeDirectory')]
            )

        self.assertNotEqual(first.asLDIF(), second.asLDIF())
        self.assertNotEqual(hash(first), hash(second))

    def testModifyOp_DNNotFound(self):
        """
        If fail to modify when the RDN does not exists.
        """
        root = self.getRoot()
        sut = delta.ModifyOp(
            'cn=nope,dc=example,dc=com',
            [delta.Add('foo', ['bar'])],
            )

        deferred = sut.patch(root)

        failure = self.failureResultOf(deferred)
        self.assertIsInstance(failure.value, ldaperrors.LDAPNoSuchObject)


class TestModificationComparison(unittest.TestCase):
    def testEquality_Add_True(self):
        a = delta.Add('k', ['b', 'c', 'd'])
        b = delta.Add('k', ['b', 'c', 'd'])
        self.assertEqual(a, b)

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

