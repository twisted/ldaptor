#!/usr/bin/python

# Ldaptor -- TODO
# Copyright (C) 2001 Matthew W. Lefkowitz
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""
Test cases for ldaptor.protocols.pureldap module.
"""

import unittest
from ldaptor.protocols import pureldap, pureber
from ldaptor.mutablestring import MutableString
import types

def s(*l):
    """Join all members of list to a string. Integer members are chr()ed"""
    r=''
    for e in l:
        if isinstance(e, types.IntType):
            e=chr(e)
        r=r+str(e)
    return r

def l(s):
    """Split a string to ord's of chars."""
    return map(lambda x: ord(x), s)

class KnownValues(unittest.TestCase):
    knownValues=( # class, args, kwargs, expected_result

        (pureldap.LDAPModifyRequest,
         [],
         { "object": 'cn=foo, dc=example, dc=com',
           "modification": [pureldap.LDAPModification_delete([('bar',)])]
           },
         [0x66, 0x2c]
         + [0x04, 0x1a]
         + l("cn=foo, dc=example, dc=com")
         + [0x30, 0x0e]
         + [0x30, 0x0c]
         + [0x0a, 0x01, 0x01]
         + [0x30, 0x07]
         + [0x04, 0x03] + l("bar")
         + [0x31, 0x00]),

        (pureldap.LDAPFilter_not,
         [],
         { "value": pureldap.LDAPFilter_present("foo"),
           },
         [0xa2, 0x05]
         + [0x87]
         + [len("foo")]
         + l("foo")),
        )

    def testToLDAP(self):
        """str(LDAPClass(...)) should give known result with known input"""
        for klass, args, kwargs, encoded in self.knownValues:
            result = apply(klass, args, kwargs)
            result = str(result)
            result = map(ord, result)
            if encoded!=result:
                raise AssertionError(encoded, result)

    def testFromLDAP(self):
        """LDAPClass(encoded="...") should give known result with known input"""
        for klass, args, kwargs, encoded in self.knownValues:
            m=MutableString(apply(s,encoded))
            m.append('foo')
            result = klass(encoded=m, berdecoder=pureber.BERDecoderContext())
            assert m=='foo'

            shouldBe = apply(klass, args, kwargs)
            #TODO shouldn't use str below
            assert str(result)==str(shouldBe), 'result is %s, should be %s' % (repr(result), repr(shouldBe))

    def testPartial(self):
        """LDAPClass(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        for klass, args, kwargs, encoded in self.knownValues:
            for i in xrange(len(encoded)):
                m=MutableString(apply(s,encoded))[:i]
                self.assertRaises(pureber.BERExceptionInsufficientData,
                                  klass,
                                  encoded=m,
                                  berdecoder=pureber.BERDecoderContext())

    def testPartialLDAPModifyRequestEncodings_old(self):
        """LDAPModifyRequest(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m=str(pureldap.LDAPModifyRequest(object='foo', modification=[pureldap.LDAPModification_delete(['bar'])]))
        for i in xrange(len(m)):
            self.assertRaises(pureber.BERExceptionInsufficientData, pureldap.LDAPModifyRequest, encoded=m[:i], berdecoder=pureber.BERDecoderContext())

if __name__ == '__main__':
    unittest.main()
