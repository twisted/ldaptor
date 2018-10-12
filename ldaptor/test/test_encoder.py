"""
    Test cases for ldaptor.encoder module
"""

from twisted.trial import unittest

import six

from ldaptor.encoder import to_bytes


class WireableObject(object):
    def toWire(self):
        return b'wire'


class EncoderTests(unittest.TestCase):

    def test_wireable_object(self):
        obj = WireableObject()
        self.assertEqual(to_bytes(obj), b'wire')

    def test_unicode_object(self):
        obj = six.u('unicode')
        self.assertEqual(to_bytes(obj), b'unicode')

    def test_bytes_object(self):
        obj = b'bytes'
        self.assertEqual(to_bytes(obj), b'bytes')
