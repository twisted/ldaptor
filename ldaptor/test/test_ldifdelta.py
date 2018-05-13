"""
Test cases for ldaptor.protocols.ldap.ldifdelta
"""

from twisted.trial import unittest
from ldaptor.protocols.ldap import ldifdelta
from ldaptor import delta, entry

class LDIFDeltaDriver(ldifdelta.LDIFDelta):
    def __init__(self):
        self.listOfCompleted = []
    def gotEntry(self, obj):
        self.listOfCompleted.append(obj)


"""
changerecord             = "changetype:" FILL
                           (change-add / change-delete /
                            change-modify / change-moddn)

change-add               = "add"                SEP 1*attrval-spec

change-delete            = "delete"             SEP

change-moddn             = ("modrdn" / "moddn") SEP
                            "newrdn:" (    FILL rdn /
                                       ":" FILL base64-rdn) SEP
                            "deleteoldrdn:" FILL ("0" / "1")  SEP
                            0*1("newsuperior:"
                            (    FILL distinguishedName /
                             ":" FILL base64-distinguishedName) SEP)

change-modify            = "modify"             SEP *mod-spec

mod-spec                 = ("add:" / "delete:" / "replace:")
                           FILL AttributeDescription SEP
                           *attrval-spec
                           "-" SEP
"""


"""
version: 1
dn: cn=foo,dc=example,dc=com
changetype: delete

"""

"""
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modrdn  #OR moddn
newrdn: rdn
deleteoldrdn: 0 #OR 1
#0..1 newsuperior: distinguishedName

"""


class TestLDIFDeltaParsing(unittest.TestCase):
    def testModification_empty(self):
        proto = LDIFDeltaDriver()
        proto.dataReceived(b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modify

""")
        proto.connectionLost()
        self.assertEqual(proto.listOfCompleted,
                         [
            delta.ModifyOp(dn='cn=foo,dc=example,dc=com'),
            ])

    def testModification_oneAdd(self):
        proto = LDIFDeltaDriver()
        proto.dataReceived(b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modify
add: foo
foo: bar
-

""")
        proto.connectionLost()
        self.assertEqual(
            proto.listOfCompleted,
            [delta.ModifyOp(dn='cn=foo,dc=example,dc=com',
                            modifications=[delta.Add('foo', ['bar']),
                                           ]),
             ])

    def testModification_twoAdds(self):
        proto = LDIFDeltaDriver()
        proto.dataReceived(b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modify
add: foo
foo: bar
-
add: thud
thud: quux
thud: baz
-

""")
        proto.connectionLost()
        self.assertEqual(
            proto.listOfCompleted,
            [delta.ModifyOp(dn='cn=foo,dc=example,dc=com',
                            modifications=[delta.Add('foo', ['bar']),
                                           delta.Add('thud', ['quux', 'baz']),
                                           ]),
             ])

    def testModification_complex(self):
        proto = LDIFDeltaDriver()
        proto.dataReceived(b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modify
delete: foo
foo: bar
-
delete: garply
-
add: thud
thud: quux
thud: baz
-
replace: waldo
-
add: foo
foo: baz
-
replace: thud
thud: xyzzy
-
add: silly
-

""")
        proto.connectionLost()
        self.assertEqual(
            proto.listOfCompleted,
            [delta.ModifyOp(dn='cn=foo,dc=example,dc=com',
                            modifications=[delta.Delete('foo', ['bar']),
                                           delta.Delete('garply'),
                                           delta.Add('thud', ['quux', 'baz']),
                                           delta.Replace('waldo'),
                                           delta.Add('foo', ['baz']),
                                           delta.Replace('thud', ['xyzzy']),
                                           delta.Add('silly'),
                                           ]),
             ])

    def testModification_fail_noDash_1(self):
        proto = LDIFDeltaDriver()
        self.assertRaises(ldifdelta.LDIFDeltaModificationMissingEndDashError,
                          proto.dataReceived,
                          b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modify
add: foo
foo: bar

""")

    def testModification_fail_noDash_2(self):
        proto = LDIFDeltaDriver()
        self.assertRaises(ldifdelta.LDIFDeltaModificationMissingEndDashError,
                          proto.dataReceived,
                          b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modify
add: foo

""")

    def testModification_fail_differentKey(self):
        proto = LDIFDeltaDriver()
        self.assertRaises(ldifdelta.LDIFDeltaModificationDifferentAttributeTypeError,
                          proto.dataReceived,
                          b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modify
add: foo
bar: quux
-

""")

    def testModification_fail_unknownModSpec(self):
        proto = LDIFDeltaDriver()
        self.assertRaises(ldifdelta.LDIFDeltaUnknownModificationError,
                          proto.dataReceived,
                          b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: modify
fiddle: foo
foo: bar
-

""")

    def testNoChangeType(self):
        """
        Raises an error is the changetype is not present.
        """
        proto = LDIFDeltaDriver()
        error = self.assertRaises(
            ldifdelta.LDIFDeltaMissingChangeTypeError,
            proto.dataReceived,
            b"""version: 1
dn: cn=foo,dc=example,dc=com
add: foo
foo: bar
-

""")
        self.assertEqual(
            ('cn=foo,dc=example,dc=com', 'add', 'foo'), error.args)


    def testNoChangetTypeEmpty(self):
        """
        Raises an error is the changetype is not present even if no
        other command are specified for the DN.
        """
        proto = LDIFDeltaDriver()

        error = self.assertRaises(
            ldifdelta.LDIFDeltaMissingChangeTypeError,
            proto.dataReceived,
            b"""version: 1
dn: cn=foo,dc=example,dc=com

""")

        self.assertEqual(('cn=foo,dc=example,dc=com',), error.args)


    def testAdd(self):
        proto = LDIFDeltaDriver()
        proto.dataReceived(b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: add
foo: bar
thud: quux
thud: baz

""")
        proto.connectionLost()
        self.assertEqual(proto.listOfCompleted,
                         [delta.AddOp(entry.BaseLDAPEntry(
            dn='cn=foo,dc=example,dc=com',
            attributes={
            'foo': ['bar'],
            'thud': ['quux', 'baz'],
            }))])

    def testAdd_fail_noAttrvals(self):
        proto = LDIFDeltaDriver()
        self.assertRaises(ldifdelta.LDIFDeltaAddMissingAttributesError,
                          proto.dataReceived, b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: add

""")


    def testDelete(self):
        """"
        Triggers a DeleteOp when the diff action is `delete`.
        """
        proto = LDIFDeltaDriver()
        proto.dataReceived(b"""\
version: 1
dn: cn=foo,dc=example,dc=com
changetype: delete

""")
        proto.connectionLost()
        self.assertEqual(proto.listOfCompleted,
                         [delta.DeleteOp(dn=b'cn=foo,dc=example,dc=com')])


    def testDeleteMalformat(self):
        """"
        Raises an error when delete change has data after the changetype.
        """
        proto = LDIFDeltaDriver()

        with self.assertRaises(
            ldifdelta.LDIFDeltaDeleteHasJunkAfterChangeTypeError
                ):
            proto.dataReceived(
b"""version: 1
dn: cn=foo,dc=example,dc=com
changetype: delete
foo: bar

""")


    def testMODRDN(self):
        """
        modrdn is not yet supported.
        """
        proto = LDIFDeltaDriver()

        with self.assertRaises(NotImplementedError):
            proto.dataReceived(
b"""version: 1
dn: cn=foo,dc=example,dc=com
changetype: modrdn

""")


    def testMODDN(self):
        """
        moddn is not yet supported.
        """
        proto = LDIFDeltaDriver()

        with self.assertRaises(NotImplementedError):
            proto.dataReceived(
b"""version: 1
dn: cn=foo,dc=example,dc=com
changetype: moddn

""")


    def testUnknownChnagetType(self):
        """
        Raises an error is the changetype is not supported.
        """
        proto = LDIFDeltaDriver()

        with self.assertRaises(ldifdelta.LDIFDeltaUnknownChangeTypeError):
            proto.dataReceived(
b"""version: 1
dn: cn=foo,dc=example,dc=com
changetype: some-random-type

""")

