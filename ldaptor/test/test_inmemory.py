"""
Test cases for ldaptor.inmemory module.
"""

from twisted.trial import unittest, util
from cStringIO import StringIO
from ldaptor import inmemory, delta, entry
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import distinguishedname, ldaperrors
from twisted.test import proto_helpers

class TestInMemoryDatabase(unittest.TestCase):
    def setUp(self):
        self.root = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))
        self.meta=self.root.addChild(
            rdn='ou=metasyntactic',
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['metasyntactic'],
            })
        self.foo=self.meta.addChild(
            rdn='cn=foo',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['foo'],
            })
        self.bar=self.meta.addChild(
            rdn='cn=bar',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['bar'],
            })

        self.empty=self.root.addChild(
            rdn='ou=empty',
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['empty'],
            })

        self.oneChild=self.root.addChild(
            rdn='ou=oneChild',
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['oneChild'],
            })
        self.theChild=self.oneChild.addChild(
            rdn='cn=theChild',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['theChild'],
            })

    def test_children_empty(self):
        d = self.empty.children()
        children = util.deferredResult(d)
        self.assertEquals(children, [])

    def test_children_oneChild(self):
        d = self.oneChild.children()
        children = util.deferredResult(d)
        self.assertEquals(len(children), 1)
        got = [e.dn for e in children]
        want = [distinguishedname.DistinguishedName('cn=theChild,ou=oneChild,dc=example,dc=com')]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_children_repeat(self):
        """Test that .children() returns a copy of the data so that modifying it does not affect behaviour."""
        d = self.oneChild.children()
        children1 = util.deferredResult(d)
        self.assertEquals(len(children1), 1)

        children1.pop()

        d = self.oneChild.children()
        children2 = util.deferredResult(d)
        self.assertEquals(len(children2), 1)

    def test_children_twoChildren(self):
        d = self.meta.children()
        children = util.deferredResult(d)
        self.assertEquals(len(children), 2)
        want = [
            distinguishedname.DistinguishedName('cn=foo,ou=metasyntactic,dc=example,dc=com'),
            distinguishedname.DistinguishedName('cn=bar,ou=metasyntactic,dc=example,dc=com'),
            ]
        got = [e.dn for e in children]
        self.assertEquals(got, want)

    def test_addChild(self):
        self.empty.addChild(
            rdn='a=b',
            attributes={
            'objectClass': ['a', 'b'],
            'a': 'b',
            })
        d = self.empty.children()
        children = util.deferredResult(d)
        self.assertEquals(len(children), 1)
        got = [e.dn for e in children]
        want = [
            distinguishedname.DistinguishedName('a=b,ou=empty,dc=example,dc=com'),
            ]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_addChild_Exists(self):
        self.assertRaises(ldaperrors.LDAPEntryAlreadyExists,
                          self.meta.addChild,
                          rdn='cn=foo',
                          attributes={
            'objectClass': ['a'],
            'cn': 'foo',
            })

    def test_parent(self):
        self.assertEquals(self.foo.parent(), self.meta)
        self.assertEquals(self.meta.parent(), self.root)
        self.assertEquals(self.root.parent(), None)


    def test_subtree_empty(self):
        d = self.empty.subtree()
        entries = util.deferredResult(d)
        self.assertEquals(len(entries), 1)

    def test_subtree_oneChild(self):
        d = self.oneChild.subtree()
        results = util.deferredResult(d)
        got = results
        want = [
            self.oneChild,
            self.theChild,
            ]
        self.assertEquals(got, want)

    def test_subtree_oneChild_cb(self):
        got = []
        d = self.oneChild.subtree(got.append)
        r = util.deferredResult(d)
        self.assertEquals(r, None)

        want = [
            self.oneChild,
            self.theChild,
            ]
        self.assertEquals(got, want)

    def test_subtree_many(self):
        d = self.root.subtree()
        results = util.deferredResult(d)
        got = results
        want = [
            self.root,
            self.oneChild,
            self.theChild,
            self.empty,
            self.meta,
            self.bar,
            self.foo,
            ]
        self.assertEquals(got, want)

    def test_subtree_many_cb(self):
        got = []
        d = self.root.subtree(callback=got.append)
        r = util.deferredResult(d)
        self.assertEquals(r, None)

        want = [
            self.root,
            self.oneChild,
            self.theChild,
            self.empty,
            self.meta,
            self.bar,
            self.foo,
            ]
        self.assertEquals(got, want)

    def test_lookup_fail(self):
        dn = distinguishedname.DistinguishedName('cn=thud,ou=metasyntactic,dc=example,dc=com')
        d = self.root.lookup(dn)
        failure = util.deferredError(d)
        failure.trap(ldaperrors.LDAPNoSuchObject)
        self.assertEquals(failure.value.message, dn)

    def test_lookup_fail_outOfTree(self):
        dn = distinguishedname.DistinguishedName('dc=invalid')
        d = self.root.lookup(dn)
        failure = util.deferredError(d)
        failure.trap(ldaperrors.LDAPNoSuchObject)
        self.assertEquals(failure.value.message, dn)

    def test_lookup_deep(self):
        dn = distinguishedname.DistinguishedName('cn=bar,ou=metasyntactic,dc=example,dc=com')
        d = self.root.lookup(dn)
        r = util.deferredResult(d)
        self.assertEquals(r, self.bar)

    def test_delete_root(self):
        newRoot = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))
        d = newRoot.delete()
        self.assertRaises(inmemory.LDAPCannotRemoveRootError,
                          util.wait, d)

    def test_delete_nonLeaf(self):
        d = self.meta.delete()
        self.assertRaises(ldaperrors.LDAPNotAllowedOnNonLeaf,
                          util.wait, d)

    def test_delete(self):
        d = self.foo.delete()
        r = util.deferredResult(d)
        self.assertEquals(r, self.foo)
        d = self.meta.children()
        r = util.deferredResult(d)
        self.assertEquals(r, [self.bar])

    def test_deleteChild(self):
        d = self.meta.deleteChild('cn=bar')
        r = util.deferredResult(d)
        self.assertEquals(r, self.bar)
        d = self.meta.children()
        r = util.deferredResult(d)
        self.assertEquals(r, [self.foo])

    def test_deleteChild_NonExisting(self):
        d = self.root.deleteChild('cn=not-exist')
        self.assertRaises(ldaperrors.LDAPNoSuchObject,
                          util.wait, d)
        
    def test_setPassword(self):
        self.foo.setPassword('s3krit', salt='\xf2\x4a')
        self.failUnless('userPassword' in self.foo)
        self.assertEquals(self.foo['userPassword'],
                          ['{SSHA}0n/Iw1NhUOKyaI9gm9v5YsO3ZInySg=='])

    def test_setPassword_noSalt(self):
        self.foo.setPassword('s3krit')
        self.failUnless('userPassword' in self.foo)
        self.assertEquals(self.foo.bind('s3krit'), True)
        self.assertEquals(self.foo.bind('s4krit'), False)

class FromLDIF(unittest.TestCase):
    def test_single(self):
        ldif = StringIO('''\
dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c

''')
        db = util.deferredResult(inmemory.fromLDIFFile(ldif))
        
        self.assertEquals(
            db.dn,
            distinguishedname.DistinguishedName('cn=foo,dc=example,dc=com'))

        d = db.children()
        children = util.deferredResult(d)
        self.assertEquals(children, [])

    def test_two(self):
        ldif = StringIO('''\
dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=foo,dc=example,dc=com
objectClass: a
cn: foo

''')
        db = util.deferredResult(inmemory.fromLDIFFile(ldif))
        
        self.assertEquals(
            db.dn,
            distinguishedname.DistinguishedName('dc=example,dc=com'))

        d = db.subtree()
        children = util.deferredResult(d)
        self.assertEquals(len(children), 2)
        want = [
            distinguishedname.DistinguishedName('dc=example,dc=com'),
            distinguishedname.DistinguishedName('cn=foo,dc=example,dc=com'),
            ]
        got = [e.dn for e in children]
        self.assertEquals(got, want)

    def test_missingNode(self):
        ldif = StringIO('''\
dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=foo,ou=nonexisting,dc=example,dc=com
objectClass: a
cn: foo

''')
        reason = util.deferredError(inmemory.fromLDIFFile(ldif))

        self.failUnless(reason.check(ldaperrors.LDAPNoSuchObject))
        self.failUnlessEqual(str(reason.value),
                             'noSuchObject: ou=nonexisting,dc=example,dc=com')

class TestDiff(unittest.TestCase):
    def testNoChange(self):
        a = inmemory.ReadOnlyInMemoryLDAPEntry('dc=example,dc=com',
                                               {
            'dc': ['example'],
            })
        b = inmemory.ReadOnlyInMemoryLDAPEntry('dc=example,dc=com',
                                               {
            'dc': ['example'],
            })
        d = a.diffTree(b)
        result = util.deferredResult(d)
        self.assertEquals(result, [])

    def testRootChange_Add(self):
        a = inmemory.ReadOnlyInMemoryLDAPEntry('dc=example,dc=com',
                                               {
            'dc': ['example'],
            })
        b = inmemory.ReadOnlyInMemoryLDAPEntry('dc=example,dc=com',
                                               {
            'dc': ['example'],
            'foo': ['bar'],
            })
        d = a.diffTree(b)
        result = util.deferredResult(d)
        self.assertEquals(result,
                          [ delta.ModifyOp('dc=example,dc=com',
                                           [
            delta.Add('foo', ['bar']),
            ]),
            ])

    def testChildChange_Add(self):
        a = inmemory.ReadOnlyInMemoryLDAPEntry('dc=example,dc=com',
                                               {
            'dc': ['example'],
            })
        a.addChild('cn=foo',
                   { 'cn': ['foo'],
                     })
        b = inmemory.ReadOnlyInMemoryLDAPEntry('dc=example,dc=com',
                                               {
            'dc': ['example'],
            })
        b.addChild('cn=foo',
                   { 'cn': ['foo'],
                     'foo': ['bar'],
                     })
        d = a.diffTree(b)
        result = util.deferredResult(d)
        self.assertEquals(result,
                          [ delta.ModifyOp('cn=foo,dc=example,dc=com',
                                           [
            delta.Add('foo', ['bar']),
            ]),
            ])
        
    def testAddChild(self):
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))

        foo=b.addChild(
            rdn='cn=foo',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['foo'],
            })
        bar=b.addChild(
            rdn='cn=bar',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['bar'],
            })

        d = a.diffTree(b)
        result = util.deferredResult(d)
        self.assertEquals(result, [
            delta.AddOp(bar),
            delta.AddOp(foo),
            ])

    def testAddSubtree(self):
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))

        foo=b.addChild(
            rdn='ou=foo',
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['foo'],
            })
        baz=foo.addChild(
            rdn='cn=baz',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['baz'],
            })
        bar=b.addChild(
            rdn='cn=bar',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['bar'],
            })

        d = a.diffTree(b)
        result = util.deferredResult(d)
        self.assertEquals(result, [
            delta.AddOp(bar),
            delta.AddOp(foo),
            delta.AddOp(baz),
            ])

    def testDeleteChild(self):
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))

        foo=a.addChild(
            rdn='cn=foo',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['foo'],
            })
        bar=a.addChild(
            rdn='cn=bar',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['bar'],
            })

        d = a.diffTree(b)
        result = util.deferredResult(d)
        self.assertEquals(result, [
            delta.DeleteOp(bar),
            delta.DeleteOp(foo),
            ])

    def testDeleteSubtree(self):
        a = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))
        b = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))

        foo=a.addChild(
            rdn='ou=foo',
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['foo'],
            })
        baz=foo.addChild(
            rdn='cn=baz',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['baz'],
            })
        bar=a.addChild(
            rdn='cn=bar',
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['bar'],
            })

        d = a.diffTree(b)
        result = util.deferredResult(d)
        self.assertEquals(result, [
            delta.DeleteOp(bar),
            delta.DeleteOp(baz),
            delta.DeleteOp(foo),
            ])
