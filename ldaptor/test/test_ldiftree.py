"""
Test cases for LDIF directory tree writing/reading.
"""

from twisted.trial import unittest, util
from twisted.python import failure
import os
from ldaptor import ldiftree, entry
from ldaptor.entry import BaseLDAPEntry
from ldaptor.protocols.ldap import distinguishedname

def writeFile(path, content):
    f = file(path, 'w')
    f.write(content)
    f.close()

class Dir2LDIF(unittest.TestCase):
    def setUp(self):
        self.tree = self.mktemp()
        os.mkdir(self.tree)
        com = os.path.join(self.tree, 'dc=com.dir')
        os.mkdir(com)
        example = os.path.join(com, 'dc=example.dir')
        os.mkdir(example)
        writeFile(os.path.join(example, 'cn=foo.entry'),
                  """\
dn: cn=foo,dc=example,dc=com
cn: foo
objectClass: top

""")
        writeFile(os.path.join(example, 'cn=bad-two-entries.entry'),
                  """\
dn: cn=bad-two-entries,dc=example,dc=com
cn: bad-two-entries
objectClass: top

dn: cn=more,dc=example,dc=com
cn: more
objectClass: top

""")
        writeFile(os.path.join(example, 'cn=bad-missing-end.entry'),
                  """\
dn: cn=bad-missing-end,dc=example,dc=com
cn: bad-missing-end
objectClass: top
""")
        writeFile(os.path.join(example, 'cn=bad-empty.entry'), '')
        writeFile(os.path.join(example, 'cn=bad-only-newline.entry'), '\n')
        sales = os.path.join(example, 'ou=Sales.dir')
        os.mkdir(sales)
        writeFile(os.path.join(sales, 'cn=sales-thingie.entry'),
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

class LDIF2Dir(unittest.TestCase):
    def setUp(self):
        self.tree = self.mktemp()
        os.mkdir(self.tree)
        com = os.path.join(self.tree, 'dc=com.dir')
        os.mkdir(com)
        example = os.path.join(com, 'dc=example.dir')
        os.mkdir(example)
        writeFile(os.path.join(example, 'cn=pre-existing.entry'),
                  """\
dn: cn=pre-existing,dc=example,dc=com
cn: pre-existing
objectClass: top

""")
        writeFile(os.path.join(example, 'ou=OrgUnit.entry'),
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

        path = os.path.join(self.tree, 'dc=com.dir', 'dc=example.dir', 'cn=foo.entry')
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
                            'ou=OrgUnit.dir', 'cn=create-me.entry')
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

        path = os.path.join(self.tree, 'dc=org.entry')
        self.failUnless(os.path.isfile(path))
        self.failUnlessEqual(file(path).read(),
                             """\
dn: dc=org
objectClass: dcObject
dc: org

""")
