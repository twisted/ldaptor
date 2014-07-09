"""
Test cases for LDIF directory tree writing/reading.
"""

import os
import random
import errno
import shutil

from twisted.trial import unittest

from ldaptor import ldiftree, entry, delta, testutil
from ldaptor.entry import BaseLDAPEntry
from ldaptor.protocols.ldap import ldaperrors, ldifprotocol


def writeFile(path, content):
    f = file(path, 'w')
    f.write(content)
    f.close()


class RandomizeListdirMixin(object):
    @classmethod
    def randomListdir(cls, *args, **kwargs):
        r = cls.__listdir(*args, **kwargs)
        random.shuffle(r)
        return r

    @classmethod
    def setUpClass(cls):
        cls.__listdir = os.listdir
        os.listdir = cls.randomListdir

    @classmethod
    def tearDownClass(cls):
        os.listdir = cls.__listdir


class Dir2LDIF(RandomizeListdirMixin, unittest.TestCase):
    def setUp(self):
        self.tree = self.mktemp()
        os.mkdir(self.tree)
        com = os.path.join(self.tree, 'dc=com.dir')
        os.mkdir(com)
        example = os.path.join(com, 'dc=example.dir')
        os.mkdir(example)
        writeFile(os.path.join(example, 'cn=foo.ldif'),
                  """\
dn: cn=foo,dc=example,dc=com
cn: foo
objectClass: top

""")
        writeFile(os.path.join(example, 'cn=bad-two-entries.ldif'),
                  """\
dn: cn=bad-two-entries,dc=example,dc=com
cn: bad-two-entries
objectClass: top

dn: cn=more,dc=example,dc=com
cn: more
objectClass: top

""")
        writeFile(os.path.join(example, 'cn=bad-missing-end.ldif'),
                  """\
dn: cn=bad-missing-end,dc=example,dc=com
cn: bad-missing-end
objectClass: top
""")
        writeFile(os.path.join(example, 'cn=bad-empty.ldif'), '')
        writeFile(os.path.join(example, 'cn=bad-only-newline.ldif'), '\n')
        sales = os.path.join(example, 'ou=Sales.dir')
        os.mkdir(sales)
        writeFile(os.path.join(sales, 'cn=sales-thingie.ldif'),
                  """\
dn: cn=sales-thingie,ou=Sales,dc=example,dc=com
cn: sales-thingie
objectClass: top

""")

    def testSimpleRead(self):
        want = BaseLDAPEntry(dn='cn=foo,dc=example,dc=com',
                             attributes={
                                 'objectClass': ['top'],
                                 'cn': ['foo'],
                             })
        d = ldiftree.get(self.tree, want.dn)
        d.addCallback(self.failUnlessEqual, want)
        return d

    def testNoAccess(self):
        os.chmod(os.path.join(self.tree,
                              'dc=com.dir',
                              'dc=example.dir',
                              'cn=foo.ldif'),
                 0)
        d = ldiftree.get(self.tree, 'cn=foo,dc=example,dc=com')

        def eb(fail):
            fail.trap(IOError)
            self.assertEquals(fail.value.errno, errno.EACCES)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    if os.getuid() == 0:
        testNoAccess.skip = "Can't test as root"

    def gettingDNRaises(self, dn, exceptionClass):
        d = ldiftree.get(self.tree, dn)

        def eb(fail):
            fail.trap(exceptionClass)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def testMultipleError(self):
        return self.gettingDNRaises(
            'cn=bad-two-entries,dc=example,dc=com',
            ldiftree.LDIFTreeEntryContainsMultipleEntries)

    def testMissingEndError(self):
        return self.gettingDNRaises(
            'cn=bad-missing-end,dc=example,dc=com',
            ldiftree.LDIFTreeEntryContainsNoEntries)

    def testEmptyError(self):
        return self.gettingDNRaises(
            'cn=bad-empty,dc=example,dc=com',
            ldiftree.LDIFTreeEntryContainsNoEntries)

    def testOnlyNewlineError(self):
        return self.gettingDNRaises(
            'cn=bad-only-newline,dc=example,dc=com',
            ldifprotocol.LDIFLineWithoutSemicolonError)

    def testTreeBranches(self):
        want = BaseLDAPEntry(dn='cn=sales-thingie,ou=Sales,dc=example,dc=com',
                             attributes={
                                 'objectClass': ['top'],
                                 'cn': ['sales-thingie'],
                             })
        d = ldiftree.get(self.tree, want.dn)
        d.addCallback(self.failUnlessEqual, want)
        return d


class LDIF2Dir(RandomizeListdirMixin, unittest.TestCase):
    def setUp(self):
        self.tree = self.mktemp()
        os.mkdir(self.tree)
        com = os.path.join(self.tree, 'dc=com.dir')
        os.mkdir(com)
        example = os.path.join(com, 'dc=example.dir')
        os.mkdir(example)
        writeFile(os.path.join(example, 'cn=pre-existing.ldif'),
                  """\
dn: cn=pre-existing,dc=example,dc=com
cn: pre-existing
objectClass: top

""")
        writeFile(os.path.join(example, 'ou=OrgUnit.ldif'),
                  """\
dn: ou=OrgUnit,dc=example,dc=com
ou: OrgUnit
objectClass: organizationalUnit

""")

    def testSimpleWrite(self):
        e = BaseLDAPEntry(dn='cn=foo,dc=example,dc=com',
                          attributes={
                              'objectClass': ['top'],
                              'cn': ['foo'],
                          })
        d = ldiftree.put(self.tree, e)
        d.addCallback(self._cb_testSimpleWrite)
        return d

    def _cb_testSimpleWrite(self, entry):
        path = os.path.join(self.tree, 'dc=com.dir', 'dc=example.dir', 'cn=foo.ldif')
        self.failUnless(os.path.isfile(path))
        self.failUnlessEqual(file(path).read(),
                             """\
dn: cn=foo,dc=example,dc=com
objectClass: top
cn: foo

""")

    def testDirCreation(self):
        e = BaseLDAPEntry(dn='cn=create-me,ou=OrgUnit,dc=example,dc=com',
                          attributes={
                              'objectClass': ['top'],
                              'cn': ['create-me'],
                          })
        d = ldiftree.put(self.tree, e)
        d.addCallback(self._cb_testDirCreation)
        return d

    def _cb_testDirCreation(self, entry):
        path = os.path.join(self.tree, 'dc=com.dir', 'dc=example.dir',
                            'ou=OrgUnit.dir', 'cn=create-me.ldif')
        self.failUnless(os.path.isfile(path))
        self.failUnlessEqual(file(path).read(),
                             """\
dn: cn=create-me,ou=OrgUnit,dc=example,dc=com
objectClass: top
cn: create-me

""")

    def testDirExists(self):
        e = BaseLDAPEntry(dn='cn=create-me,ou=OrgUnit,dc=example,dc=com',
                          attributes={
                              'objectClass': ['top'],
                              'cn': ['create-me'],
                          })
        dirpath = os.path.join(self.tree, 'dc=com.dir', 'dc=example.dir',
                               'ou=OrgUnit.dir')
        os.mkdir(dirpath)
        d = ldiftree.put(self.tree, e)
        d.addCallback(self._cb_testDirExists, dirpath)
        return d

    def _cb_testDirExists(self, entry, dirpath):
        path = os.path.join(dirpath, 'cn=create-me.ldif')
        self.failUnless(os.path.isfile(path))
        self.failUnlessEqual(file(path).read(),
                             """\
dn: cn=create-me,ou=OrgUnit,dc=example,dc=com
objectClass: top
cn: create-me

""")

    def testMissingLinkError(self):
        e = BaseLDAPEntry(dn='cn=bad-create,ou=NoSuchOrgUnit,dc=example,dc=com',
                          attributes={
                              'objectClass': ['top'],
                              'cn': ['bad-create'],
                          })
        d = ldiftree.put(self.tree, e)
        d.addCallbacks(self._cb_testMissingLinkError,
                       self._eb_testMissingLinkError)
        return d

    def _cb_testMissingLinkError(self):
        raise unittest.FailTest('Should have raised an exception.')

    def _eb_testMissingLinkError(self, fail):
        fail.trap(ldiftree.LDIFTreeNoSuchObject)

    def testAddTopLevel(self):
        e = BaseLDAPEntry(dn='dc=org',
                          attributes={
                              'objectClass': ['dcObject'],
                              'dc': ['org'],
                          })
        d = ldiftree.put(self.tree, e)
        d.addCallback(self._cb_testAddTopLevel)
        return d

    def _cb_testAddTopLevel(self, entry):
        path = os.path.join(self.tree, 'dc=org.ldif')
        self.failUnless(os.path.isfile(path))
        self.failUnlessEqual(file(path).read(),
                             """\
dn: dc=org
objectClass: dcObject
dc: org

""")


class Tree(RandomizeListdirMixin, unittest.TestCase):
    # TODO share the actual tests with inmemory and any other
    # implementations of the same interface
    def setUp(self):
        self.tree = self.mktemp()
        os.mkdir(self.tree)
        com = os.path.join(self.tree, 'dc=com.dir')
        os.mkdir(com)
        example = os.path.join(com, 'dc=example.dir')
        os.mkdir(example)
        meta = os.path.join(example, 'ou=metasyntactic.dir')
        os.mkdir(meta)
        writeFile(os.path.join(example, 'ou=metasyntactic.ldif'),
                  """\
dn: ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
ou: metasyntactic

""")
        foo = os.path.join(meta, 'cn=foo.dir')
        writeFile(os.path.join(meta, 'cn=foo.ldif'),
                  """\
dn: cn=foo,ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
cn: foo

""")
        bar = os.path.join(meta, 'cn=bar.dir')
        writeFile(os.path.join(meta, 'cn=bar.ldif'),
                  """\
dn: cn=bar,ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
cn: bar

""")
        empty = os.path.join(example, 'ou=empty.dir')
        writeFile(os.path.join(example, 'ou=empty.ldif'),
                  """\
dn: ou=empty,dc=example,dc=com
objectClass: a
objectClass: b
ou: empty

""")
        oneChild = os.path.join(example, 'ou=oneChild.dir')
        os.mkdir(oneChild)
        writeFile(os.path.join(example, 'ou=oneChild.ldif'),
                  """\
dn: ou=oneChild,dc=example,dc=com
objectClass: a
objectClass: b
ou: oneChild

""")
        theChild = os.path.join(oneChild, 'cn=theChild.dir')
        writeFile(os.path.join(oneChild, 'cn=theChild.ldif'),
                  """\
dn: cn=theChild,ou=oneChild,dc=example,dc=com
objectClass: a
objectClass: b
cn: theChild

""")
        self.root = ldiftree.LDIFTreeEntry(self.tree)
        self.example = ldiftree.LDIFTreeEntry(example, 'dc=example,dc=com')
        self.empty = ldiftree.LDIFTreeEntry(empty, 'ou=empty,dc=example,dc=com')
        self.meta = ldiftree.LDIFTreeEntry(meta, 'ou=metasyntactic,dc=example,dc=com')
        self.foo = ldiftree.LDIFTreeEntry(foo, 'cn=foo,ou=metasyntactic,dc=example,dc=com')
        self.bar = ldiftree.LDIFTreeEntry(bar, 'cn=bar,ou=metasyntactic,dc=example,dc=com')
        self.oneChild = ldiftree.LDIFTreeEntry(oneChild, 'ou=oneChild,dc=example,dc=com')
        self.theChild = ldiftree.LDIFTreeEntry(theChild, 'cn=theChild,ou=oneChild,dc=example,dc=com')

    def test_children_empty(self):
        d = self.empty.children()

        def cb(children):
            self.assertEquals(children, [])

        d.addCallback(cb)
        return d

    def test_children_oneChild(self):
        d = self.oneChild.children()
        d.addCallback(self._cb_test_children_oneChild)
        return d

    def _cb_test_children_oneChild(self, children):
        self.assertEquals(len(children), 1)
        got = [e.dn for e in children]
        want = ['cn=theChild,ou=oneChild,dc=example,dc=com']
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_children_repeat(self):
        """Test that .children() returns a copy of the data so that modifying it does not affect behaviour."""
        d = self.oneChild.children()
        d.addCallback(self._cb_test_children_repeat_1)
        return d

    def _cb_test_children_repeat_1(self, children1):
        self.assertEquals(len(children1), 1)

        children1.pop()

        d = self.oneChild.children()
        d.addCallback(self._cb_test_children_repeat_2)
        return d

    def _cb_test_children_repeat_2(self, children2):
        self.assertEquals(len(children2), 1)

    def test_children_twoChildren(self):
        d = self.meta.children()
        d.addCallback(self._cb_test_children_twoChildren)
        return d

    def _cb_test_children_twoChildren(self, children):
        self.assertEquals(len(children), 2)
        want = [
            'cn=foo,ou=metasyntactic,dc=example,dc=com',
            'cn=bar,ou=metasyntactic,dc=example,dc=com',
        ]
        got = [e.dn for e in children]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_children_twoChildren_callback(self):
        children = []
        d = self.meta.children(callback=children.append)
        d.addCallback(self._cb_test_children_twoChildren_callback, children)
        return d

    def _cb_test_children_twoChildren_callback(self, r, children):
        self.assertIdentical(r, None)
        self.assertEquals(len(children), 2)
        want = [
            'cn=foo,ou=metasyntactic,dc=example,dc=com',
            'cn=bar,ou=metasyntactic,dc=example,dc=com',
        ]
        got = [e.dn for e in children]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_children_noAccess_dir_noRead(self):
        os.chmod(self.meta.path, 0300)
        d = self.meta.children()

        def eb(fail):
            fail.trap(OSError)
            self.assertEquals(fail.value.errno, errno.EACCES)
            os.chmod(self.meta.path, 0755)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    if os.getuid() == 0:
        test_children_noAccess_dir_noRead.skip = "Can't test as root"

    def test_children_noAccess_dir_noExec(self):
        os.chmod(self.meta.path, 0600)
        d = self.meta.children()

        def eb(fail):
            fail.trap(IOError)
            self.assertEquals(fail.value.errno, errno.EACCES)
            os.chmod(self.meta.path, 0755)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    if os.getuid() == 0:
        test_children_noAccess_dir_noExec.skip = "Can't test as root"

    def test_children_noAccess_file(self):
        os.chmod(os.path.join(self.meta.path, 'cn=foo.ldif'), 0)
        d = self.meta.children()

        def eb(fail):
            fail.trap(IOError)
            self.assertEquals(fail.value.errno, errno.EACCES)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    if os.getuid() == 0:
        test_children_noAccess_file.skip = "Can't test as root"

    def test_addChild(self):
        self.empty.addChild(
            rdn='a=b',
            attributes={
                'objectClass': ['a', 'b'],
                'a': 'b',
            })
        d = self.empty.children()
        d.addCallback(self._cb_test_addChild)
        return d

    def _cb_test_addChild(self, children):
        self.assertEquals(len(children), 1)
        got = [e.dn for e in children]
        want = [
            'a=b,ou=empty,dc=example,dc=com',
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
        self.assertEquals(self.meta.parent(), self.example)
        self.assertEquals(self.root.parent(), None)

    def test_subtree_empty(self):
        d = self.empty.subtree()
        d.addCallback(self._cb_test_subtree_empty)
        return d

    def _cb_test_subtree_empty(self, entries):
        self.assertEquals(len(entries), 1)

    def test_subtree_oneChild(self):
        d = self.oneChild.subtree()
        d.addCallback(self._cb_test_subtree_oneChild)
        return d

    def _cb_test_subtree_oneChild(self, results):
        got = results
        want = [
            self.oneChild,
            self.theChild,
        ]
        self.assertEquals(got, want)

    def test_subtree_oneChild_cb(self):
        got = []
        d = self.oneChild.subtree(got.append)
        d.addCallback(self._cb_test_subtree_oneChild_cb, got)
        return d

    def _cb_test_subtree_oneChild_cb(self, r, got):
        self.assertEquals(r, None)

        want = [
            self.oneChild,
            self.theChild,
        ]
        self.assertEquals(got, want)

    def test_subtree_many(self):
        d = self.example.subtree()
        d.addCallback(self._cb_test_subtree_many)
        return d

    def _cb_test_subtree_many(self, results):
        got = results
        want = [
            self.example,
            self.oneChild,
            self.theChild,
            self.empty,
            self.meta,
            self.bar,
            self.foo,
        ]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_subtree_many_cb(self):
        got = []
        d = self.example.subtree(callback=got.append)
        d.addCallback(self._cb_test_subtree_many_cb, got)
        return d

    def _cb_test_subtree_many_cb(self, r, got):
        self.assertEquals(r, None)

        want = [
            self.example,
            self.oneChild,
            self.theChild,
            self.empty,
            self.meta,
            self.bar,
            self.foo,
        ]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_lookup_fail(self):
        dn = 'cn=thud,ou=metasyntactic,dc=example,dc=com'
        d = self.root.lookup(dn)

        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            self.assertEquals(fail.value.message, dn)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_lookup_fail_outOfTree(self):
        dn = 'dc=invalid'
        d = self.root.lookup(dn)

        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            self.assertEquals(fail.value.message, dn)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_lookup_fail_outOfTree_2(self):
        dn = 'dc=invalid'
        d = self.example.lookup(dn)

        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            self.assertEquals(fail.value.message, dn)

        d.addCallbacks(testutil.mustRaise, eb)

    def test_lookup_fail_multipleError(self):
        writeFile(os.path.join(self.example.path,
                               'cn=bad-two-entries.ldif'),
                  """\
dn: cn=bad-two-entries,dc=example,dc=com
cn: bad-two-entries
objectClass: top

dn: cn=more,dc=example,dc=com
cn: more
objectClass: top

""")
        self.assertRaises(
            ldiftree.LDIFTreeEntryContainsMultipleEntries,
            self.example.lookup,
            'cn=bad-two-entries,dc=example,dc=com')

    def test_lookup_fail_emptyError(self):
        writeFile(os.path.join(self.example.path,
                               'cn=bad-empty.ldif'),
                  "")
        self.assertRaises(
            ldiftree.LDIFTreeEntryContainsNoEntries,
            self.example.lookup,
            'cn=bad-empty,dc=example,dc=com')

    def test_lookup_deep(self):
        dn = 'cn=bar,ou=metasyntactic,dc=example,dc=com'
        d = self.root.lookup(dn)
        d.addCallback(self._cb_test_lookup_deep)
        return d

    def _cb_test_lookup_deep(self, r):
        self.assertEquals(r, self.bar)

    def test_delete_root(self):
        d = self.root.delete()

        def eb(fail):
            fail.trap(ldiftree.LDAPCannotRemoveRootError)

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
        d.addCallback(self._cb_test_delete_1)
        return d

    def _cb_test_delete_1(self, r):
        self.assertEquals(r, self.foo)
        d = self.meta.children()
        d.addCallback(self._cb_test_delete_2)
        return d

    def _cb_test_delete_2(self, r):
        self.assertEquals(r, [self.bar])

    def test_deleteChild(self):
        d = self.meta.deleteChild('cn=bar')
        d.addCallback(self._cb_test_deleteChild_1)
        return d

    def _cb_test_deleteChild_1(self, r):
        self.assertEquals(r, self.bar)
        d = self.meta.children()
        d.addCallback(self._cb_test_deleteChild_2)
        return d

    def _cb_test_deleteChild_2(self, r):
        self.assertEquals(r, [self.foo])

    def test_deleteChild_NonExisting(self):
        d = self.root.deleteChild('cn=not-exist')

        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)

        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_setPassword(self):
        self.foo.setPassword('s3krit', salt='\xf2\x4a')
        self.failUnless('userPassword' in self.foo)
        self.assertEquals(self.foo['userPassword'],
                          ['{SSHA}0n/Iw1NhUOKyaI9gm9v5YsO3ZInySg=='])

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

    def test_diffTree_self(self):
        d = self.root.diffTree(self.root)
        d.addCallback(self.assertEquals, [])
        return d

    def test_diffTree_copy(self):
        otherDir = self.mktemp()
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)
        d = self.root.diffTree(other)
        d.addCallback(self.assertEquals, [])
        return d

    def test_diffTree_addChild(self):
        otherDir = self.mktemp()
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)
        e = entry.BaseLDAPEntry(dn='cn=foo,dc=example,dc=com')
        d = ldiftree.put(otherDir, e)

        def cb1(dummy):
            return other.lookup('cn=foo,dc=example,dc=com')

        d.addCallback(cb1)

        def cb2(r):
            d1 = self.root.diffTree(other)
            d1.addCallback(self.assertEquals, [delta.AddOp(r)])
            return d1

        d.addCallback(cb2)
        return d

    def test_diffTree_delChild(self):
        otherDir = self.mktemp()
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)

        d = other.lookup('ou=empty,dc=example,dc=com')

        def cb1(otherEmpty):
            return otherEmpty.delete()

        d.addCallback(cb1)

        def cb2(dummy):
            return self.root.diffTree(other)

        d.addCallback(cb2)

        def cb3(got):
            self.assertEquals(got, [delta.DeleteOp(self.empty)])

        d.addCallback(cb3)
        return d

    def test_diffTree_edit(self):
        otherDir = self.mktemp()
        shutil.copytree(self.tree, otherDir)
        other = ldiftree.LDIFTreeEntry(otherDir)

        d = other.lookup('ou=empty,dc=example,dc=com')

        def cb1(otherEmpty):
            otherEmpty['foo'] = ['bar']
            return otherEmpty.commit()

        d.addCallback(cb1)

        def cb2(dummy):
            return self.root.diffTree(other)

        d.addCallback(cb2)

        def cb3(got):
            self.assertEquals(got, [
                delta.ModifyOp(self.empty.dn,
                               [delta.Add('foo', ['bar'])],
                               )])

        d.addCallback(cb3)
        return d

    def test_move_noChildren_sameSuperior(self):
        d = self.empty.move('ou=moved,dc=example,dc=com')

        def getChildren(dummy):
            return self.example.children()

        d.addCallback(getChildren)
        d.addCallback(set)
        d.addCallback(self.assertEquals, set([self.meta, BaseLDAPEntry(
            dn='ou=moved,dc=example,dc=com',
            attributes={'objectClass': ['a', 'b'],
                        'ou': ['moved'],
                        }),
            self.oneChild
        ]))
        return d

    def test_move_children_sameSuperior(self):
        d = self.meta.move('ou=moved,dc=example,dc=com')

        def getChildren(dummy):
            return self.example.children()

        d.addCallback(getChildren)
        d.addCallback(set)
        d.addCallback(self.assertEquals, set([
                      BaseLDAPEntry(dn='ou=moved,dc=example,dc=com',
                                     attributes={'objectClass': ['a', 'b'],
                                                 'ou': ['moved'],
                                                 }
                                     ),
                       self.empty,
                       self.oneChild
                       ]))
        return d

    def test_move_noChildren_newSuperior(self):
        d = self.empty.move('ou=moved,ou=oneChild,dc=example,dc=com')

        def getChildren(dummy):
            return self.example.children()

        d.addCallback(getChildren)
        d.addCallback(set)
        d.addCallback(self.assertEquals, set([self.meta, self.oneChild]))

        def getChildren2(dummy):
            return self.oneChild.children()

        d.addCallback(getChildren2)
        d.addCallback(set)
        d.addCallback(self.assertEquals, set([self.theChild, BaseLDAPEntry(
            dn='ou=moved,ou=oneChild,dc=example,dc=com',
            attributes={'objectClass': ['a', 'b'],
                        'ou': ['moved'],
                        })]))
        return d

    def test_move_children_newSuperior(self):
        d = self.meta.move('ou=moved,ou=oneChild,dc=example,dc=com')

        def getChildren(dummy):
            return self.example.children()

        d.addCallback(getChildren)
        d.addCallback(set)
        d.addCallback(self.assertEquals, set([self.empty, self.oneChild]))

        def getChildren2(dummy):
            return self.oneChild.children()

        d.addCallback(getChildren2)
        d.addCallback(set)
        d.addCallback(self.assertEquals, set([self.theChild,
                                          BaseLDAPEntry(dn='ou=moved,ou=oneChild,dc=example,dc=com',
                                                        attributes={'objectClass': ['a', 'b'],
                                                                    'ou': ['moved'],
                                                                    })]))
        return d
