#!/usr/bin/python

"""
Test cases for bidirdict module
"""

import unittest
from ldaptor.bidirdict import BidirDict

class SimpleOps(unittest.TestCase):
    def testCreate(self):
        d=BidirDict({1:2, 3:4})
        assert d[1]==2
        assert d[3]==4
        assert d.reverse[2]==1
        assert d.reverse[4]==3

class KwArgs(unittest.TestCase):
    def testCreate(self):
        d=BidirDict({'foo': 'bar', 'quux': 'thud'},
                    foo='baz', thud='foobar')

        assert d['foo']=='baz'
        assert d['quux']=='thud'
        assert d['thud']=='foobar'

        assert d.reverse['baz']=='foo'
        assert d.reverse['thud']=='quux'
        assert d.reverse['foobar']=='thud'

if __name__ == '__main__':
    unittest.main()
