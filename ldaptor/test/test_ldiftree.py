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


def write_file(path, content):
    f = file(path, 'w')
    f.write(content)
    f.close()


class RandomizeListdirMixin(object):
    @classmethod
    def random_list_dir(cls, *args, **kwargs):
        r = cls.__listdir(*args, **kwargs)
        random.shuffle(r)
        return r

    @classmethod
    def setUpClass(cls):
        cls.__listdir = os.listdir
        os.listdir = cls.random_list_dir

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
        write_file(os.path.join(example, 'cn=foo.ldif'),
                   """\
dn: cn=foo,dc=example,dc=com
cn: foo
objectClass: top

""")
        write_file(os.path.join(example, 'cn=bad-two-entries.ldif'),
                   """\
dn: cn=bad-two-entries,dc=example,dc=com
cn: bad-two-entries
objectClass: top

dn: cn=more,dc=example,dc=com
cn: more
objectClass: top

""")
        write_file(os.path.join(example, 'cn=bad-missing-end.ldif'),
                   """\
dn: cn=bad-missing-end,dc=example,dc=com
cn: bad-missing-end
objectClass: top
""")
        write_file(os.path.join(example, 'cn=bad-empty.ldif'), '')
        write_file(os.path.join(example, 'cn=bad-only-newline.ldif'), '\n')
        sales = os.path.join(example, 'ou=Sales.dir')
        os.mkdir(sales)
        write_file(os.path.join(sales, 'cn=sales-thingie.ldif'),
                   """\
dn: cn=sales-thingie,ou=Sales,dc=example,dc=com
cn: sales-thingie
objectClass: top

""")

    def test_simple_read(self):
        want = BaseLDAPEntry(dn='cn=foo,dc=example,dc=com',
                             attributes={
                             'objectClass': ['top'],
                             'cn': ['foo'],
                             })
        d = ldiftree.get(self.tree, want.dn)
        d.addCallback(self.failUnlessEqual, want)
        return d

    def test_no_access(self):
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

    def getting_dn_raises(self, dn, exceptionClass):
        d = ldiftree.get(self.tree, dn)

        def eb(fail):
            fail.trap(exceptionClass)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_multiple_error(self):
        return self.getting_dn_raises(
            'cn=bad-two-entries,dc=example,dc=com',
            ldiftree.LDIFTreeEntryContainsMultipleEntries)

    def test_missing_end_error(self):
        return self.getting_dn_raises(
            'cn=bad-missing-end,dc=example,dc=com',
            ldiftree.LDIFTreeEntryContainsNoEntries)

    def test_empty_error(self):
        return self.getting_dn_raises(
            'cn=bad-empty,dc=example,dc=com',
            ldiftree.LDIFTreeEntryContainsNoEntries)

    def test_only_newline_error(self):
        return self.getting_dn_raises(
            'cn=bad-only-newline,dc=example,dc=com',
            ldifprotocol.LDIFLineWithoutSemicolonError)

    def test_tree_branches(self):
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
        write_file(os.path.join(example, 'cn=pre-existing.ldif'),
                   """\
dn: cn=pre-existing,dc=example,dc=com
cn: pre-existing
objectClass: top

""")
        write_file(os.path.join(example, 'ou=OrgUnit.ldif'),
                   """\
dn: ou=OrgUnit,dc=example,dc=com
ou: OrgUnit
objectClass: organizationalUnit

""")

    def test_simple_write(self):
        e = BaseLDAPEntry(dn='cn=foo,dc=example,dc=com',
                          attributes={
                          'objectClass': ['top'],
                          'cn': ['foo'],
                          })
        d = ldiftree.put(self.tree, e)
        d.addCallback(self._cb_test_simple_write)
        return d

    def _cb_test_simple_write(self, entry_object):
        path = os.path.join(self.tree, 'dc=com.dir', 'dc=example.dir', 'cn=foo.ldif')
        self.failUnless(os.path.isfile(path))
        self.failUnlessEqual(file(path).read(),
                             """\
dn: cn=foo,dc=example,dc=com
objectClass: top
cn: foo

""")

    def test_dir_creation(self):
        e = BaseLDAPEntry(dn='cn=create-me,ou=OrgUnit,dc=example,dc=com',
                          attributes={
                          'objectClass': ['top'],
                          'cn': ['create-me'],
                          })
        d = ldiftree.put(self.tree, e)
        d.addCallback(self._cb_test_dir_creation)
        return d

    def _cb_test_dir_creation(self, entry_object):
        path = os.path.join(self.tree, 'dc=com.dir', 'dc=example.dir',
                            'ou=OrgUnit.dir', 'cn=create-me.ldif')
        self.failUnless(os.path.isfile(path))
        self.failUnlessEqual(file(path).read(),
                             """\
dn: cn=create-me,ou=OrgUnit,dc=example,dc=com
objectClass: top
cn: create-me

""")

    def test_dir_exists(self):
        e = BaseLDAPEntry(dn='cn=create-me,ou=OrgUnit,dc=example,dc=com',
                          attributes={
                          'objectClass': ['top'],
                          'cn': ['create-me'],
                          })
        dir_path = os.path.join(self.tree, 'dc=com.dir', 'dc=example.dir',
                                'ou=OrgUnit.dir')
        os.mkdir(dir_path)
        d = ldiftree.put(self.tree, e)
        d.addCallback(self._cb_test_dir_exists, dir_path)
        return d

    def _cb_test_dir_exists(self, entry_object, dir_path):
        path = os.path.join(dir_path, 'cn=create-me.ldif')
        self.failUnless(os.path.isfile(path))
        self.failUnlessEqual(file(path).read(),
                             """\
dn: cn=create-me,ou=OrgUnit,dc=example,dc=com
objectClass: top
cn: create-me

""")

    def test_missing_link_error(self):
        e = BaseLDAPEntry(dn='cn=bad-create,ou=NoSuchOrgUnit,dc=example,dc=com',
                          attributes={
                          'objectClass': ['top'],
                          'cn': ['bad-create'],
                          })
        d = ldiftree.put(self.tree, e)
        d.addCallbacks(self._cb_test_missing_link_error,
                       self._eb_test_missing_link_error)
        return d

    def _cb_test_missing_link_error(self):
        raise unittest.FailTest('Should have raised an exception.')

    def _eb_test_missing_link_error(self, fail):
        fail.trap(ldiftree.LDIFTreeNoSuchObject)

    def test_add_top_level(self):
        e = BaseLDAPEntry(dn='dc=org',
                          attributes={
                          'objectClass': ['dcObject'],
                          'dc': ['org'],
                          })
        d = ldiftree.put(self.tree, e)
        d.addCallback(self._cb_test_add_top_level)
        return d

    def _cb_test_add_top_level(self, entry_object):
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
        write_file(os.path.join(example, 'ou=metasyntactic.ldif'),
                   """\
dn: ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
ou: metasyntactic

""")
        foo = os.path.join(meta, 'cn=foo.dir')
        write_file(os.path.join(meta, 'cn=foo.ldif'),
                   """\
dn: cn=foo,ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
cn: foo

""")
        bar = os.path.join(meta, 'cn=bar.dir')
        write_file(os.path.join(meta, 'cn=bar.ldif'),
                   """\
dn: cn=bar,ou=metasyntactic,dc=example,dc=com
objectClass: a
objectClass: b
cn: bar

""")
        empty = os.path.join(example, 'ou=empty.dir')
        write_file(os.path.join(example, 'ou=empty.ldif'),
                   """\
dn: ou=empty,dc=example,dc=com
objectClass: a
objectClass: b
ou: empty

""")
        one_child = os.path.join(example, 'ou=oneChild.dir')
        os.mkdir(one_child)
        write_file(os.path.join(example, 'ou=oneChild.ldif'),
                   """\
dn: ou=oneChild,dc=example,dc=com
objectClass: a
objectClass: b
ou: oneChild

""")
        the_child = os.path.join(one_child, 'cn=theChild.dir')
        write_file(os.path.join(one_child, 'cn=theChild.ldif'),
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
        self.one_child = ldiftree.LDIFTreeEntry(one_child, 'ou=oneChild,dc=example,dc=com')
        self.the_child = ldiftree.LDIFTreeEntry(the_child, 'cn=theChild,ou=oneChild,dc=example,dc=com')

    def test_children_empty(self):
        d = self.empty.children()
        
        def cb(children):
            self.assertEquals(children, [])
        d.addCallback(cb)
        return d

    def test_children_one_child(self):
        d = self.one_child.children()
        d.addCallback(self._cb_test_children_one_child)
        return d

    def _cb_test_children_one_child(self, children):
        self.assertEquals(len(children), 1)
        got = [e.dn for e in children]
        want = ['cn=theChild,ou=oneChild,dc=example,dc=com']
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_children_repeat(self):
        """Test that .children() returns a copy of the data so that modifying it does not affect behaviour."""
        d = self.one_child.children()
        d.addCallback(self._cb_test_children_repeat_1)
        return d

    def _cb_test_children_repeat_1(self, children1):
        self.assertEquals(len(children1), 1)

        children1.pop()

        d = self.one_child.children()
        d.addCallback(self._cb_test_children_repeat_2)
        return d

    def _cb_test_children_repeat_2(self, children2):
        self.assertEquals(len(children2), 1)

    def test_children_two_children(self):
        d = self.meta.children()
        d.addCallback(self._cb_test_children_two_children)
        return d

    def _cb_test_children_two_children(self, children):
        self.assertEquals(len(children), 2)
        want = [
            'cn=foo,ou=metasyntactic,dc=example,dc=com',
            'cn=bar,ou=metasyntactic,dc=example,dc=com',
        ]
        got = [e.dn for e in children]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_children_two_children_callback(self):
        children = []
        d = self.meta.children(callback=children.append)
        d.addCallback(self._cb_test_children_two_children_callback, children)
        return d

    def _cb_test_children_two_children_callback(self, r, children):
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

    def test_children_no_access_dir_no_read(self):
        os.chmod(self.meta.path, 0300)
        d = self.meta.children()
        
        def eb(fail):
            fail.trap(OSError)
            self.assertEquals(fail.value.errno, errno.EACCES)
            os.chmod(self.meta.path, 0755)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    if os.getuid() == 0:
        test_children_no_access_dir_no_read.skip = "Can't test as root"

    def test_children_no_access_dir_no_exec(self):
        os.chmod(self.meta.path, 0600)
        d = self.meta.children()
        
        def eb(fail):
            fail.trap(IOError)
            self.assertEquals(fail.value.errno, errno.EACCES)
            os.chmod(self.meta.path, 0755)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    if os.getuid() == 0:
        test_children_no_access_dir_no_exec.skip = "Can't test as root"

    def test_children_no_access_file(self):
        os.chmod(os.path.join(self.meta.path, 'cn=foo.ldif'), 0)
        d = self.meta.children()

        def eb(fail):
            fail.trap(IOError)
            self.assertEquals(fail.value.errno, errno.EACCES)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    if os.getuid() == 0:
        test_children_no_access_file.skip = "Can't test as root"

    def test_add_child(self):
        self.empty.addChild(
            rdn='a=b',
            attributes={
                'objectClass': ['a', 'b'],
                'a': 'b',
            })
        d = self.empty.children()
        d.addCallback(self._cb_test_add_child)
        return d

    def _cb_test_add_child(self, children):
        self.assertEquals(len(children), 1)
        got = [e.dn for e in children]
        want = [
            'a=b,ou=empty,dc=example,dc=com',
        ]
        got.sort()
        want.sort()
        self.assertEquals(got, want)

    def test_add_child_exists(self):
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

    def test_subtree_one_child(self):
        d = self.one_child.subtree()
        d.addCallback(self._cb_test_subtree_one_child)
        return d

    def _cb_test_subtree_one_child(self, results):
        got = results
        want = [
            self.one_child,
            self.the_child,
        ]
        self.assertEquals(got, want)

    def test_subtree_one_child_cb(self):
        got = []
        d = self.one_child.subtree(got.append)
        d.addCallback(self._cb_test_subtree_one_child_cb, got)
        return d

    def _cb_test_subtree_one_child_cb(self, r, got):
        self.assertEquals(r, None)

        want = [
            self.one_child,
            self.the_child,
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
            self.one_child,
            self.the_child,
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
            self.one_child,
            self.the_child,
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

    def test_lookup_fail_out_of_tree(self):
        dn = 'dc=invalid'
        d = self.root.lookup(dn)
        
        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            self.assertEquals(fail.value.message, dn)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_lookup_fail_out_of_tree_2(self):
        dn = 'dc=invalid'
        d = self.example.lookup(dn)

        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            self.assertEquals(fail.value.message, dn)
        d.addCallbacks(testutil.mustRaise, eb)

    def test_lookup_fail_multiple_error(self):
        write_file(os.path.join(self.example.path,
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

    def test_lookup_fail_empty_error(self):
        write_file(os.path.join(self.example.path,
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

    def test_delete_non_leaf(self):
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

    def test_delete_child(self):
        d = self.meta.deleteChild('cn=bar')
        d.addCallback(self._cb_test_delete_child_1)
        return d

    def _cb_test_delete_child_1(self, r):
        self.assertEquals(r, self.bar)
        d = self.meta.children()
        d.addCallback(self._cb_test_delete_child_2)
        return d

    def _cb_test_delete_child_2(self, r):
        self.assertEquals(r, [self.foo])

    def test_delete_child_non_existing(self):
        d = self.root.deleteChild('cn=not-exist')

        def eb(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_set_password(self):
        self.foo.setPassword('s3krit', salt='\xf2\x4a')
        self.failUnless('userPassword' in self.foo)
        self.assertEquals(self.foo['userPassword'],
                          ['{SSHA}0n/Iw1NhUOKyaI9gm9v5YsO3ZInySg=='])

    def test_set_password_no_salt(self):
        self.foo.setPassword('s3krit')
        self.failUnless('userPassword' in self.foo)
        d = self.foo.bind('s3krit')
        d.addCallback(self.assertIdentical, self.foo)
        d.addCallback(lambda _: self.foo.bind('s4krit'))
        
        def eb(fail):
            fail.trap(ldaperrors.LDAPInvalidCredentials)
        d.addCallbacks(testutil.mustRaise, eb)
        return d

    def test_diff_tree_self(self):
        d = self.root.diffTree(self.root)
        d.addCallback(self.assertEquals, [])
        return d

    def test_diff_tree_copy(self):
        other_dir = self.mktemp()
        shutil.copytree(self.tree, other_dir)
        other = ldiftree.LDIFTreeEntry(other_dir)
        d = self.root.diffTree(other)
        d.addCallback(self.assertEquals, [])
        return d

    def test_diff_tree_add_child(self):
        other_dir = self.mktemp()
        shutil.copytree(self.tree, other_dir)
        other = ldiftree.LDIFTreeEntry(other_dir)
        e = entry.BaseLDAPEntry(dn='cn=foo,dc=example,dc=com')
        d = ldiftree.put(other_dir, e)

        def cb1(dummy):
            return other.lookup('cn=foo,dc=example,dc=com')
        d.addCallback(cb1)

        def cb2(r):
            d1 = self.root.diffTree(other)
            d1.addCallback(self.assertEquals, [delta.AddOp(r)])
            return d1
        d.addCallback(cb2)
        return d

    def test_diff_tree_del_child(self):
        other_dir = self.mktemp()
        shutil.copytree(self.tree, other_dir)
        other = ldiftree.LDIFTreeEntry(other_dir)

        d = other.lookup('ou=empty,dc=example,dc=com')

        def cb1(other_empty):
            return other_empty.delete()
        d.addCallback(cb1)

        def cb2(dummy):
            return self.root.diffTree(other)
        d.addCallback(cb2)

        def cb3(got):
            self.assertEquals(got, [delta.DeleteOp(self.empty)])
        d.addCallback(cb3)
        return d

    def test_diff_tree_edit(self):
        other_dir = self.mktemp()
        shutil.copytree(self.tree, other_dir)
        other = ldiftree.LDIFTreeEntry(other_dir)

        d = other.lookup('ou=empty,dc=example,dc=com')

        def cb1(other_empty):
            other_empty['foo'] = ['bar']
            return other_empty.commit()
        d.addCallback(cb1)

        def cb2(dummy):
            return self.root.diffTree(other)
        d.addCallback(cb2)

        def cb3(got):
            self.assertEquals(got, [delta.ModifyOp(self.empty.dn, [delta.Add('foo', ['bar'])], ), ])
        d.addCallback(cb3)
        return d

    def test_move_no_children_same_superior(self):
        d = self.empty.move('ou=moved,dc=example,dc=com')
        
        def get_children(dummy):
            return self.example.children()
        d.addCallback(get_children)
        d.addCallback(set)
        d.addCallback(self.assertEquals, {self.meta, BaseLDAPEntry(
            dn='ou=moved,dc=example,dc=com',
            attributes={'objectClass': ['a', 'b'], 'ou': ['moved'], }), self.one_child})
        return d

    def test_move_children_same_superior(self):
        d = self.meta.move('ou=moved,dc=example,dc=com')

        def get_children(dummy):
            return self.example.children()
        d.addCallback(get_children)
        d.addCallback(set)
        d.addCallback(self.assertEquals, {BaseLDAPEntry(dn='ou=moved,dc=example,dc=com',
                                                        attributes={'objectClass': ['a', 'b'],
                                                                    'ou': ['moved'],
                                                                    }), self.empty, self.one_child})
        return d

    def test_move_no_children_new_superior(self):
        d = self.empty.move('ou=moved,ou=oneChild,dc=example,dc=com')

        def get_children(dummy):
            return self.example.children()
        d.addCallback(get_children)
        d.addCallback(set)
        d.addCallback(self.assertEquals, {self.meta, self.one_child})

        def get_children2(dummy):
            return self.one_child.children()
        d.addCallback(get_children2)
        d.addCallback(set)
        d.addCallback(self.assertEquals, {self.the_child, BaseLDAPEntry(
            dn='ou=moved,ou=oneChild,dc=example,dc=com',
            attributes={'objectClass': ['a', 'b'], 'ou': ['moved'], })})
        return d

    def test_move_children_new_superior(self):
        d = self.meta.move('ou=moved,ou=oneChild,dc=example,dc=com')

        def get_children(dummy):
            return self.example.children()
        d.addCallback(get_children)
        d.addCallback(set)
        d.addCallback(self.assertEquals, {self.empty, self.one_child})

        def get_children2(dummy):
            return self.one_child.children()
        d.addCallback(get_children2)
        d.addCallback(set)
        d.addCallback(self.assertEquals, {self.the_child, BaseLDAPEntry(dn='ou=moved,ou=oneChild,dc=example,dc=com',
                                                                        attributes={'objectClass': ['a', 'b'],
                                                                                    'ou': ['moved'],
                                                                                    })})
        return d
