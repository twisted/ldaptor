"""
    Test cases for ldaptor.encoder module
"""

from twisted.trial import unittest

import six

from ldaptor._encoder import to_bytes, WireStrAlias


class WireableObject(object):
    """
    Object with bytes representation as a constant toWire value
    """

    def toWire(self):
        return b'wire'


class EncoderTests(unittest.TestCase):

    def test_wireable_object(self):
        """
        to_bytes function use object`s toWire method
        to get its bytes representation if it has one
        """
        obj = WireableObject()
        self.assertEqual(to_bytes(obj), b'wire')

    def test_unicode_object(self):
        """
        unicode string is encoded to utf-8 if passed
        to to_bytes function
        """
        obj = six.u('unicode')
        self.assertEqual(to_bytes(obj), b'unicode')

    def test_bytes_object(self):
        """
        byte string is returned without changes
        if passed to to_bytes function
        """
        obj = b'bytes'
        self.assertEqual(to_bytes(obj), b'bytes')


class WireStrAliasTests(unittest.TestCase):

    def test_toWire_not_implemented(self):
        """
        WireStrAlias.toWire is an abstract method and raises NotImplementedError
        """
        obj = WireStrAlias()
        self.assertRaises(NotImplementedError, obj.toWire)
