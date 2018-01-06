"""
Test cases for ldaptor.inmemory module.
"""
from io import BytesIO

from twisted.trial import unittest
import six

from ldaptor import inmemory, delta, testutil
from ldaptor.protocols.ldap import distinguishedname, ldaperrors

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
        d.addCallback(lambda actual: six.assertCountEqual(self, actual, []))
        return d

    def test_children_oneChild(self):
        d = self.oneChild.children()
        def cb(children):
            self.assertEqual(len(children), 1)
            got = [e.dn for e in children]
            want = [distinguishedname.DistinguishedName('cn=theChild,ou=oneChild,dc=example,dc=com')]
            got.sort()
            want.sort()
            six.assertCountEqual(self, got, want)
        d.addCallback(cb)
        return d

    def test_children_repeat(self):
        """Test that .children() returns a copy of the data so that modifying it does not affect behaviour."""
        d = self.oneChild.children()
        def cb1(children1):
            self.assertEqual(len(children1), 1)
            children1.pop()

            d = self.oneChild.children()
            return d
        d.addCallback(cb1)

        def cb2(children2):
            self.assertEqual(len(children2), 1)
        d.addCallback(cb2)
        return d

    def test_children_twoChildren(self):
        d = self.meta.children()
        def cb(children):
            self.assertEqual(len(children), 2)
            want = [
                distinguishedname.DistinguishedName('cn=foo,ou=metasyntactic,dc=example,dc=com'),
                distinguishedname.DistinguishedName('cn=bar,ou=metasyntactic,dc=example,dc=com'),
                ]
            got = [e.dn for e in children]
            six.assertCountEqual(self, got, want)
        d.addCallback(cb)
        return d

    def test_addChild(self):
        self.empty.addChild(
            rdn='a=b',
            attributes={
            'objectClass': ['a', 'b'],
            'a': 'b',
            })
        d = self.empty.children()
        def cb(children):
            self.assertEqual(len(children), 1)
            got = [e.dn for e in children]
            want = [
                distinguishedname.DistinguishedName('a=b,ou=empty,dc=example,dc=com'),
                ]
            got.sort()
            want.sort()
            six.assertCountEqual(self, got, want)
        d.addCallback(cb)
        return d

    def test_addChild_Exists(self):
        self.assertRaises(ldaperrors.LDAPEntryAlreadyExists,
                          self.meta.addChild,
                          rdn='cn=foo',
                          attributes={
            'objectClass': ['a'],
            'cn': 'foo',
            })

    def test_parent(self):
        self.assertEqual(self.foo.parent(), self.meta)
        self.assertEqual(self.meta.parent(), self.root)
        self.assertEqual(self.root.parent(), None)


    def test_subtree_empty(self):
        d = self.empty.subtree()
        def cb(entries):
            self.assertEqual(len(entries), 1)
        d.addCallback(cb)
        return d

    def test_subtree_oneChild(self):
        d = self.oneChild.subtree()
        d.addCallback(lambda actual: six.assertCountEqual(
            self,
            actual,
            [
            self.oneChild,
            self.theChild,
            ]))
        return d

    def test_subtree_oneChild_cb(self):
        got = []
        d = self.oneChild.subtree(got.append)
        d.addCallback(self.assertEqual, None)
        def cb(dummy):
            want = [
                self.oneChild,
                self.theChild,
                ]
            six.assertCountEqual(self, got, want)
        d.addCallback(cb)
        return d

    def test_subtree_many(self):
        d = self.root.subtree()
        def cb(results):
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
            six.assertCountEqual(self, got, want)
        d.addCallback(cb)
        return d

    def test_subtree_many_cb(self):
        got = []
        d = self.root.subtree(callback=got.append)
        def cb(r):
            self.assertEqual(r, None)

            want = [
                self.root,
                self.oneChild,
                self.theChild,
                self.empty,
                self.meta,
                self.bar,
                self.foo,
                ]
            six.assertCountEqual(self, got, want)
        d.addCallback(cb)
        return d

    def test_lookup_fail(self):
        dn = distinguishedname.DistinguishedName('cn=thud,ou=metasyntactic,dc=example,dc=com')
        d = self.root.lookup(dn)
        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            self.assertEqual(fail.value.message, dn)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_lookup_fail_outOfTree(self):
        dn = distinguishedname.DistinguishedName('dc=invalid')
        d = self.root.lookup(dn)
        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            self.assertEqual(fail.value.message, dn)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_lookup_deep(self):
        dn = distinguishedname.DistinguishedName('cn=bar,ou=metasyntactic,dc=example,dc=com')
        d = self.root.lookup(dn)
        d.addCallback(self.assertEqual, self.bar)
        return d

    def test_delete_root(self):
        newRoot = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn=distinguishedname.DistinguishedName('dc=example,dc=com'))
        d = newRoot.delete()
        def eb(fail):
            fail.trap(inmemory.LDAPCannotRemoveRootError)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_delete_nonLeaf(self):
        d = self.meta.delete()
        def eb(fail):
            fail.trap(ldaperrors.LDAPNotAllowedOnNonLeaf)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_delete(self):
        d = self.foo.delete()
        d.addCallback(self.assertEqual, self.foo)
        d.addCallback(lambda _: self.meta.children())
        d.addCallback(lambda actual: six.assertCountEqual(
            self, actual, [self.bar]))
        return d

    def test_deleteChild(self):
        d = self.meta.deleteChild('cn=bar')
        d.addCallback(self.assertEqual, self.bar)
        d.addCallback(lambda _: self.meta.children())
        d.addCallback(lambda actual: six.assertCountEqual(
            self, actual, [self.foo]))
        return d

    def test_deleteChild_NonExisting(self):
        d = self.root.deleteChild('cn=not-exist')
        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_setPassword(self):
        self.foo.setPassword('s3krit', salt=b'\xf2\x4a')
        self.assertEqual(
            self.foo['userPassword'],
            [b'{SSHA}0n/Iw1NhUOKyaI9gm9v5YsO3ZInySg=='])

    def test_setPassword_noSalt(self):
        self.foo.setPassword('s3krit')
        self.failUnless('userPassword' in self.foo)
        d = self.foo.bind('s3krit')
        d.addCallback(self.assertIdentical, self.foo)
        d.addCallback(lambda _: self.foo.bind('s4krit'))
        def eb(fail):
            fail.trap(ldaperrors.LDAPInvalidCredentials)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def testSearch_withCallback(self):
        got = []
        d = self.root.search(filterText='(|(cn=foo)(cn=bar))',
                             callback=got.append)
        def cb(r):
            self.assertEqual(r, None)

            want = [
                self.bar,
                self.foo,
                ]
            six.assertCountEqual(self, got, want)
        d.addCallback(cb)
        return d

    def testSearch_withoutCallback(self):
        d = self.root.search(filterText='(|(cn=foo)(cn=bar))')
        d.addCallback(lambda actual: six.assertCountEqual(
            self,
            actual,
            [
            self.bar,
            self.foo,
            ]))
        return d

    def test_move_noChildren_sameSuperior(self):
        d = self.empty.move('ou=moved,dc=example,dc=com')
        def getChildren(dummy):
            return self.root.children()
        d.addCallback(getChildren)
        d.addCallback(lambda actual: six.assertCountEqual(
            self,
            actual,
            [
            self.meta,
            inmemory.ReadOnlyInMemoryLDAPEntry(
            dn='ou=moved,dc=example,dc=com',
            attributes={ 'objectClass': ['a', 'b'],
                         'ou': ['moved'],
            }),
            self.oneChild,
            ]))
        return d

    def test_move_children_sameSuperior(self):
        d = self.meta.move('ou=moved,dc=example,dc=com')
        def getChildren(dummy):
            return self.root.children()
        d.addCallback(getChildren)
        d.addCallback(lambda actual: six.assertCountEqual(
            self,
            actual,
            [
            inmemory.ReadOnlyInMemoryLDAPEntry(
            dn='ou=moved,dc=example,dc=com',
            attributes={ 'objectClass': ['a', 'b'],
                         'ou': ['moved'],
            }),
            self.empty,
            self.oneChild,
            ]))
        return d


    def test_move_noChildren_newSuperior(self):
        d = self.empty.move('ou=moved,ou=oneChild,dc=example,dc=com')
        def getChildren(dummy):
            return self.root.children()
        d.addCallback(getChildren)
        d.addCallback(lambda actual: six.assertCountEqual(
            self,
            actual,
            [
            self.meta,
            self.oneChild,
            ]))
        def getChildren2(dummy):
            return self.oneChild.children()
        d.addCallback(getChildren2)
        d.addCallback(lambda actual: six.assertCountEqual(
            self,
            actual,
            [
            self.theChild,
            inmemory.ReadOnlyInMemoryLDAPEntry(
            dn='ou=moved,ou=oneChild,dc=example,dc=com',
            attributes={ 'objectClass': ['a', 'b'],
                         'ou': ['moved'],
            }),
            ]))
        return d

    def test_move_children_newSuperior(self):
        d = self.meta.move('ou=moved,ou=oneChild,dc=example,dc=com')
        def getChildren(dummy):
            return self.root.children()
        d.addCallback(getChildren)
        d.addCallback(lambda actual: six.assertCountEqual(
            self,
            actual,
            [
            self.empty,
            self.oneChild,
            ]))
        def getChildren2(dummy):
            return self.oneChild.children()
        d.addCallback(getChildren2)
        d.addCallback(lambda actual: six.assertCountEqual(
            self,
            actual,
            [
            self.theChild,
            inmemory.ReadOnlyInMemoryLDAPEntry(
            dn='ou=moved,ou=oneChild,dc=example,dc=com',
            attributes={ 'objectClass': ['a', 'b'],
                         'ou': ['moved'],
            }),
            ]))
        return d

    def test_commit(self):
        """ReadOnlyInMemoryLDAPEntry.commit() succeeds immediately."""
        self.meta['foo'] = ['bar']
        d = self.meta.commit()
        self.failUnless(d.called)

class FromLDIF(unittest.TestCase):
    def test_single(self):
        ldif = BytesIO(b'''\
dn: cn=foo,dc=example,dc=com
objectClass: a
objectClass: b
aValue: a
aValue: b
bValue: c

''')
        d = inmemory.fromLDIFFile(ldif)
        def cb1(db):
            self.assertEqual(
                db.dn,
                distinguishedname.DistinguishedName('cn=foo,dc=example,dc=com'))
            return db.children()
        d.addCallback(cb1)
        d.addCallback(self.assertEqual, [])
        return d

    def test_two(self):
        ldif = BytesIO(b'''\
dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=foo,dc=example,dc=com
objectClass: a
cn: foo

''')
        d = inmemory.fromLDIFFile(ldif)
        def cb1(db):
            self.assertEqual(
                db.dn,
                distinguishedname.DistinguishedName('dc=example,dc=com'))
            return db.subtree()
        d.addCallback(cb1)
        def cb2(children):
            self.assertEqual(len(children), 2)
            want = [
                distinguishedname.DistinguishedName('dc=example,dc=com'),
                distinguishedname.DistinguishedName('cn=foo,dc=example,dc=com'),
                ]
            got = [e.dn for e in children]
            six.assertCountEqual(self, got, want)
        d.addCallback(cb2)
        return d

    def test_missingNode(self):
        ldif = BytesIO(b'''\
dn: dc=example,dc=com
objectClass: dcObject
dc: example

dn: cn=foo,ou=nonexisting,dc=example,dc=com
objectClass: a
cn: foo

''')
        d = inmemory.fromLDIFFile(ldif)
        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            self.failUnlessEqual(
                str(fail.value),
                'noSuchObject: ou=nonexisting,dc=example,dc=com')
        d.addCallbacks(testutil.mustRaise, eb)
        return d


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
        d.addCallback(self.assertEqual, [])
        return d

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
        d.addCallback(self.assertEqual,
                      [ delta.ModifyOp('dc=example,dc=com',
                                       [
            delta.Add('foo', ['bar']),
            ]),
                        ])
        return d

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
        d.addCallback(self.assertEqual,
                      [ delta.ModifyOp('cn=foo,dc=example,dc=com',
                                       [
            delta.Add('foo', ['bar']),
            ]),
                        ])
        return d

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
        d.addCallback(self.assertEqual, [
            delta.AddOp(bar),
            delta.AddOp(foo),
            ])
        return d

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
        d.addCallback(self.assertEqual, [
            delta.AddOp(bar),
            delta.AddOp(foo),
            delta.AddOp(baz),
            ])
        return d

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
        d.addCallback(self.assertEqual, [
            delta.DeleteOp(bar),
            delta.DeleteOp(foo),
            ])
        return d

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
        d.addCallback(self.assertEqual, [
            delta.DeleteOp(bar),
            delta.DeleteOp(baz),
            delta.DeleteOp(foo),
            ])
        return d
