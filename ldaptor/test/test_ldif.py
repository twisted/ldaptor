"""
    Test cases for ldaptor.protocols.ldap.ldif module
"""

import base64

from twisted.trial import unittest

from ldaptor.protocols.ldap.ldif import attributeAsLDIF, asLDIF, manyAsLDIF


def encode(value):
    return b"".join(base64.encodebytes(value).split(b"\n"))


class WireableObject:
    """
    Object with bytes representation as a constant toWire value
    """

    def toWire(self):
        return b"wire"


class AttributeAsLDIFTests(unittest.TestCase):
    """
    Converting pairs of attribute keys and values to LDIF.
    The result is a byte string with key and value
    separated by a semicolon and a space.
    In several special cases value is base64 encoded and separated
    from key by two semicolons and a space.
    """

    def test_byte_string(self):
        """Key and value are byte strings"""
        result = attributeAsLDIF(b"some key", b"some value")
        self.assertEqual(result, b"some key: some value\n")

    def test_unicode_string(self):
        """Key and value are unicode strings"""
        result = attributeAsLDIF("another key", "another value")
        self.assertEqual(result, b"another key: another value\n")

    def test_wireable_object(self):
        """Value is an object with toWire method returning its bytes representation"""
        result = attributeAsLDIF("dn", WireableObject())
        self.assertEqual(result, b"dn: wire\n")

    def test_startswith_special_character(self):
        """
        Value is a string starting with one of the reserved characters.
        Returned value is base64 encoded.
        """
        for c in b"\0", b"\n", b"\r", b" ", b":", b"<":

            value = c + b"value"
            result = attributeAsLDIF(b"key", value)
            self.assertEqual(result, b"key:: %s\n" % encode(value))

    def test_endswith_special_character(self):
        """
        Value is a string ending with one of the reserved characters.
        Returned value is base64 encoded.
        """
        for c in b"\0", b"\n", b"\r", b" ":

            value = b"value" + c
            result = attributeAsLDIF(b"key", value)
            self.assertEqual(result, b"key:: %s\n" % encode(value))

    def test_contains_special_characters(self):
        """
        Value is a string with one of the reserved characters
        somewhere in its middle.
        Returned value is base64 encoded.
        """
        for c in b"\0", b"\n", b"\r":

            value = b"foo" + c + b"bar"
            result = attributeAsLDIF(b"key", value)
            self.assertEqual(result, b"key:: %s\n" % encode(value))

    def test_contains_nonprintable_characters(self):
        """
        Value is a string containing nonprintable characters.
        Returned value is base64 encoded.
        """
        result = attributeAsLDIF(b"key", b"val\xFFue")
        self.assertEqual(result, b"key:: %s\n" % encode(b"val\xFFue"))


class AsLDIFTests(unittest.TestCase):
    """
    Converting LDAP objects to LDIF.
    Object consists of DN and pairs of attribute keys and lists of values.
    The result is a number of lines in LDIF format for every key/value pair
    including DN.
    """

    def test_byte_string(self):
        """DN and attribute keys and values are byte strings"""
        attributes = [
            (b"key1", [b"value11", b"value12"]),
            (b"key2", [b"value21", b"value22"]),
        ]
        result = asLDIF(b"entry", attributes)
        self.assertEqual(
            result,
            b"""\
dn: entry
key1: value11
key1: value12
key2: value21
key2: value22

""",
        )

    def test_unicode_string(self):
        """DN and attribute keys and values are unicode string"""
        attributes = [
            ("key1", ["value11", "value12"]),
            ("key2", ["value21", "value22"]),
        ]
        result = asLDIF("entry", attributes)
        self.assertEqual(
            result,
            b"""\
dn: entry
key1: value11
key1: value12
key2: value21
key2: value22

""",
        )

    def test_wireable_object(self):
        """
        DN and attribute values are objects with
        toWire method returning bytes representation
        """
        attributes = [
            (b"key", [WireableObject()]),
        ]
        result = asLDIF(WireableObject(), attributes)
        self.assertEqual(result, b"dn: wire\nkey: wire\n\n")


class ManyAsLDIFTests(unittest.TestCase):
    """
    Converting multiple LDAP objects to LDIF.
    Every object consists of pair of DN and pairs of attribute keys and lists of values.
    The result is a number of blocks representing each object in LDIF format
    separated by an empty lines.
    The result contains a header with version number separated from other blocks
    by an empty line.
    """

    def test_multiple_objects(self):
        objects = [
            (
                b"object1",
                (
                    (b"foo1", (b"value11", b"value12")),
                    (b"foo2", (b"value21", b"value22")),
                ),
            ),
            (
                b"object2",
                (
                    (b"bar1", (b"value31", b"value32")),
                    (b"bar2", (b"value41", b"value42")),
                ),
            ),
        ]
        result = manyAsLDIF(objects)
        self.assertEqual(
            result,
            b"""\
version: 1

dn: object1
foo1: value11
foo1: value12
foo2: value21
foo2: value22

dn: object2
bar1: value31
bar1: value32
bar2: value41
bar2: value42

""",
        )
