"""
    Test cases for ldaptor.encoder module
"""

from twisted.trial import unittest

import six

import ldaptor._encoder


class WireableObject:
    """
    Object with bytes representation as a constant toWire value
    """

    def toWire(self):
        return b'wire'


class TextObject(ldaptor._encoder.TextStrAlias):
    """
    Object with human readable representation as a constant getText value
    """

    def getText(self):
        return 'text'


class EncoderTests(unittest.TestCase):

    def test_wireable_object(self):
        """
        to_bytes function use object`s toWire method
        to get its bytes representation if it has one
        """
        obj = WireableObject()
        self.assertEqual(ldaptor._encoder.to_bytes(obj), b'wire')

    def test_unicode_object(self):
        """
        unicode string is encoded to utf-8 if passed
        to to_bytes function
        """
        obj = 'unicode'
        self.assertEqual(ldaptor._encoder.to_bytes(obj), b'unicode')

    def test_bytes_object(self):
        """
        byte string is returned without changes
        if passed to to_bytes function
        """
        obj = b'bytes'
        self.assertEqual(ldaptor._encoder.to_bytes(obj), b'bytes')

    def test_int_object(self):
        """
        integer is converted to a string representation, then encoded to bytes
        if passed to to_bytes function
        """
        obj = 42
        self.assertEqual(ldaptor._encoder.to_bytes(obj), b'42')


class WireStrAliasTests(unittest.TestCase):

    def test_toWire_not_implemented(self):
        """
        WireStrAlias.toWire is an abstract method and raises NotImplementedError
        """
        obj = ldaptor._encoder.WireStrAlias()
        self.assertRaises(NotImplementedError, obj.toWire)


class TextStrAliasTests(unittest.TestCase):

    def test_deprecation_warning(self):
        str(TextObject())
        msg = 'TextObject.__str__ method is deprecated and will not be used ' \
              'for getting human readable representation in the future ' \
              'releases, use TextObject.getText instead'
        warnings = self.flushWarnings()
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]['category'], DeprecationWarning)
        self.assertEqual(warnings[0]['message'], msg)

    def test_getText_not_implemented(self):
        """
        TextStrAlias.getText is an abstract method and raises NotImplementedError
        """
        obj = ldaptor._encoder.TextStrAlias()
        self.assertRaises(NotImplementedError, obj.getText)
