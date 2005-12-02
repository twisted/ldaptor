"""
Test cases for LDIF directory tree writing/reading.
"""

from twisted.trial import unittest, util
from twisted.python import failure
import os, random, errno
from ldaptor import ldiftree, entry
from ldaptor.entry import BaseLDAPEntry
from ldaptor.protocols.ldap import distinguishedname, ldaperrors

def writeFile(path, content):
    f = file(path, 'w')
    f.write(content)
    f.close()

class RandomizeListdirMixin(object):
    def randomListdir(self, *args, **kwargs):
        r = self.__listdir(*args, **kwargs)
        random.shuffle(r)
        return r

    def setUpClass(self):
        self.__listdir = os.listdir
        os.listdir = self.randomListdir

    def tearDownClass(self):
        os.listdir = self.__listdir

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

    def get(self, dn):
        d = ldiftree.get(self.tree, dn)
        try:
            entry = util.deferredResult(d)
        except failure.Failure, e:
            raise e.value
        return entry

    def testSimpleRead(self):
	want = BaseLDAPEntry(dn='cn=foo,dc=example,dc=com',
                             attributes={
	    'objectClass': ['top'],
	    'cn': ['foo'],
	    })
        e = self.get(want.dn)
        self.failUnlessEqual(e, want)

    def testNoAccess(self):
        os.chmod(os.path.join(self.tree,
                              'dc=com.dir',
                              'dc=example.dir',
                              'cn=foo.ldif'),
                 0)
        e = self.assertRaises(
            IOError,
            self.get,
            distinguishedname.DistinguishedName(
            'cn=foo,dc=example,dc=com'))
        self.assertEquals(e.errno, errno.EACCES)

    def testMultipleError(self):
        self.assertRaises(
            ldiftree.LDIFTreeEntryContainsMultipleEntries,
            self.get,
            distinguishedname.DistinguishedName(
            'cn=bad-two-entries,dc=example,dc=com'))

    def testMissingEndError(self):
        self.assertRaises(
            ldiftree.LDIFTreeEntryContainsNoEntries,
            self.get,
            distinguishedname.DistinguishedName(
            'cn=bad-missing-end,dc=example,dc=com'))

    def testEmptyError(self):
        self.assertRaises(
            ldiftree.LDIFTreeEntryContainsNoEntries,
            self.get,
            distinguishedname.DistinguishedName(
            'cn=bad-missing-end,dc=example,dc=com'))

    def testOnlyNewlineError(self):
        self.assertRaises(
            ldiftree.LDIFTreeEntryContainsNoEntries,
            self.get,
            distinguishedname.DistinguishedName(
            'cn=bad-missing-end,dc=example,dc=com'))

    def testTreeBranches(self):
        want = BaseLDAPEntry(dn='cn=sales-thingie,ou=Sales,dc=example,dc=com',
                             attributes={
	    'objectClass': ['top'],
	    'cn': ['sales-thingie'],
	    })
        e = self.get(want.dn)
        self.failUnlessEqual(e, want)

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
        try:
            entry = util.deferredResult(d)
        except failure.Failure, exc:
            raise exc.value

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
        try:
            entry = util.deferredResult(d)
        except failure.Failure, exc:
            raise exc.value

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
        try:
            entry = util.deferredResult(d)
        except failure.Failure, exc:
            raise exc.value

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
        def block(d):
            try:
                util.deferredResult(d)
            except failure.Failure, e:
                raise e.value
        self.assertRaises(
            ldiftree.LDIFTreeNoSuchObject,
            block, d)

    def testAddTopLevel(self):
	e = BaseLDAPEntry(dn='dc=org',
                          attributes={
	    'objectClass': ['dcObject'],
	    'dc': ['org'],
	    })
        d = ldiftree.put(self.tree, e)
        try:
            entry = util.deferredResult(d)
        except failure.Failure, exc:
            raise exc.value

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
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_children_twoChildren_callback(self):
        children = []
        d = self.meta.children(callback=children.append)
        r = util.deferredResult(d)
        self.assertIdentical(r, None)
        self.assertEquals(len(children), 2)
        want = [
            distinguishedname.DistinguishedName('cn=foo,ou=metasyntactic,dc=example,dc=com'),
            distinguishedname.DistinguishedName('cn=bar,ou=metasyntactic,dc=example,dc=com'),
            ]
        got = [e.dn for e in children]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_children_noAccess(self):
        os.chmod(os.path.join(self.meta.path, 'cn=foo.ldif'), 0)
        d = self.meta.children()
        e = self.assertRaises(IOError,
                              util.wait, d)
        self.assertEquals(e.errno, errno.EACCES)

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
        self.assertEquals(self.meta.parent(), self.example)
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
        d = self.example.subtree()
        results = util.deferredResult(d)
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
        r = util.deferredResult(d)
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

    def test_lookup_fail_outOfTree_2(self):
        dn = distinguishedname.DistinguishedName('dc=invalid')
        d = self.example.lookup(dn)
        failure = util.deferredError(d)
        failure.trap(ldaperrors.LDAPNoSuchObject)
        self.assertEquals(failure.value.message, dn)

    def test_lookup_deep(self):
        dn = distinguishedname.DistinguishedName('cn=bar,ou=metasyntactic,dc=example,dc=com')
        d = self.root.lookup(dn)
        r = util.deferredResult(d)
        self.assertEquals(r, self.bar)

    def test_delete_root(self):
        d = self.root.delete()
        self.assertRaises(ldiftree.LDAPCannotRemoveRootError,
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
        d = self.foo.bind('s3krit')
        r = util.deferredResult(d)
        self.assertIdentical(r, self.foo)
        d = self.foo.bind('s4krit')
        fail = util.deferredError(d)
        fail.trap(ldaperrors.LDAPInvalidCredentials)
