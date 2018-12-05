"""
    Test cases for ldaptor.encoder module
"""

from twisted.trial import unittest

import six

import ldaptor._encoder


class WireableObject(object):
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
        return u'text'


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
        obj = six.u('unicode')
        self.assertEqual(ldaptor._encoder.to_bytes(obj), b'unicode')

    def test_bytes_object(self):
        """
        byte string is returned without changes
        if passed to to_bytes function
        """
        obj = b'bytes'
        self.assertEqual(ldaptor._encoder.to_bytes(obj), b'bytes')


class WireStrAliasTests(unittest.TestCase):

    def test_toWire_not_implemented(self):
        """
        WireStrAlias.toWire is an abstract method and raises NotImplementedError
        """
        obj = ldaptor._encoder.WireStrAlias()
        self.assertRaises(NotImplementedError, obj.toWire)


class TextStrAliasTests(unittest.TestCase):

    def test_deprecation_warning(self):
        obj = TextObject()
        msg = 'TextObject.__str__ method is deprecated and will not be used ' \
              'for getting human readable representation in the future ' \
              'releases, use TextObject.getText instead'
        self.assertWarns(DeprecationWarning, msg, ldaptor._encoder.__file__, obj.__str__)

    def test_getText_not_implemented(self):
        """
        TextStrAlias.getText is an abstract method and raises NotImplementedError
        """
        obj = ldaptor._encoder.TextStrAlias()
        self.assertRaises(NotImplementedError, obj.getText)
