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
Test cases for ldaptor.protocols.pureber module.
"""

from twisted.trial import unittest
from ldaptor.protocols import pureber
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

class BerLengths(unittest.TestCase):
    knownValues=(
        (0, [0]),
        (1, [1]),
        (100, [100]),
        (126, [126]),
        (127, [127]),
        (128, [0x80|1, 128]),
        (129, [0x80|1, 129]),
        (255, [0x80|1, 255]),
        (256, [0x80|2, 1, 0]),
        (257, [0x80|2, 1, 1]),
        (65535, [0x80|2, 0xFF, 0xFF]),
        (65536, [0x80|3, 0x01, 0x00, 0x00]),
        (256**127-1, [0x80|127]+127*[0xFF]),
        )

    def testToBER(self):
        for integer, encoded in self.knownValues:
            got = pureber.int2berlen(integer)
            got = str(got)
            got = map(ord, got)
            self.assertEquals(got, encoded)

    def testFromBER(self):
        for integer, encoded in self.knownValues:
            m=s(*encoded)
            got, bytes = pureber.berDecodeLength(m)
            self.assertEquals(bytes, len(m))
            self.assertEquals(got, integer)

    def testPartialBER(self):
        m=str(pureber.int2berlen(3*256))
        assert len(m)==3
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeLength, m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeLength, m[:1])

        m=str(pureber.int2berlen(256**100-1))
        assert len(m)==101
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeLength, m[:100])

class BERBaseEquality(unittest.TestCase):
    valuesToTest=(
        (pureber.BERInteger, [0]),
        (pureber.BERInteger, [1]),
        (pureber.BERInteger, [4000]),
        (pureber.BERSequence, [[pureber.BERInteger(1000), pureber.BERInteger(2000)]]),
        (pureber.BERSequence, [[pureber.BERInteger(2000), pureber.BERInteger(1000)]]),
        (pureber.BEROctetString, ["foo"]),
        (pureber.BEROctetString, ["b"+chr(0xe4)+chr(0xe4)]),
        )

    def testBERBaseEquality(self):
        """BER objects equal BER objects with same type and content"""
        for class_, args in self.valuesToTest:
            x=class_(*args)
            y=class_(*args)
            assert x==x
            assert x==y

    def testBERBaseInEquality(self):
        """BER objects do not equal BER objects with different type or content"""
        for i in xrange(len(self.valuesToTest)):
            for j in xrange(len(self.valuesToTest)):
                if i!=j:
                    i_class, i_args = self.valuesToTest[i]
                    j_class, j_args = self.valuesToTest[j]
                    x=i_class(*i_args)
                    y=j_class(*j_args)
                    assert x!=y


class BERIntegerKnownValues(unittest.TestCase):
    knownValues=(
        (0, [0x02, 0x01, 0]),
        (1, [0x02, 0x01, 1]),
        (2, [0x02, 0x01, 2]),
        (125, [0x02, 0x01, 125]),
        (126, [0x02, 0x01, 126]),
        (127, [0x02, 0x01, 127]),
        (-1, [0x02, 0x01, 256-1]),
        (-2, [0x02, 0x01, 256-2]),
        (-3, [0x02, 0x01, 256-3]),
        (-126, [0x02, 0x01, 256-126]),
        (-127, [0x02, 0x01, 256-127]),
        (-128, [0x02, 0x01, 256-128]),
        (-129, [0x02, 0x02, 256-1, 256-129]),
        (128, [0x02, 0x02, 0, 128]),
        (256, [0x02, 0x02, 1, 0]),
        )

    def testToBERIntegerKnownValues(self):
        """str(BERInteger(n)) should give known result with known input"""
        for integer, encoded in self.knownValues:
            result = pureber.BERInteger(integer)
            result = str(result)
            result = map(ord, result)
            assert encoded==result

    def testFromBERIntegerKnownValues(self):
        """BERInteger(encoded="...") should give known result with known input"""
        for integer, encoded in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEquals(bytes, len(m))
            assert isinstance(result, pureber.BERInteger)
            result = result.value
            assert integer==result

    def testPartialBERIntegerEncodings(self):
        """BERInteger(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m=str(pureber.BERInteger(42))
        assert len(m)==3
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEquals((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))

class BERIntegerSanityCheck(unittest.TestCase):
    def testSanity(self):
        """BERInteger(encoded=BERInteger(n)).value==n for -1000..1000"""
        for n in range(-1000, 1001, 10):
            encoded = str(pureber.BERInteger(n))
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), encoded)
            self.assertEquals(bytes, len(encoded))
            assert isinstance(result, pureber.BERInteger)
            result = result.value
            assert n==result




class BEROctetStringKnownValues(unittest.TestCase):
    knownValues=(
        ("", [0x04, 0]),
        ("foo", [0x04, 3]+l("foo")),
        (100*"x", [0x04, 100]+l(100*"x")),
        )

    def testToBEROctetStringKnownValues(self):
        """str(BEROctetString(n)) should give known result with known input"""
        for st, encoded in self.knownValues:
            result = pureber.BEROctetString(st)
            result = str(result)
            result = map(ord, result)
            assert encoded==result

    def testFromBEROctetStringKnownValues(self):
        """BEROctetString(encoded="...") should give known result with known input"""
        for st, encoded in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEquals(bytes, len(m))
            assert isinstance(result, pureber.BEROctetString)
            result = str(result)
            result = map(ord, result)
            assert encoded==result

    def testPartialBEROctetStringEncodings(self):
        """BEROctetString(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m=str(pureber.BEROctetString("x"))
        assert len(m)==3
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEquals((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))

class BEROctetStringSanityCheck(unittest.TestCase):
    def testSanity(self):
        """BEROctetString(encoded=BEROctetString(n*'x')).value==n*'x' for some values of n"""
        for n in 0,1,2,3,4,5,6,100,126,127,128,129,1000,2000:
            encoded = str(pureber.BEROctetString(n*'x'))
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), encoded)
            self.assertEquals(bytes, len(encoded))
            assert isinstance(result, pureber.BEROctetString)
            result = result.value
            assert n*'x'==result












class BERNullKnownValues(unittest.TestCase):
    def testToBERNullKnownValues(self):
        """str(BERNull()) should give known result"""
        result = pureber.BERNull()
        result = str(result)
        result = map(ord, result)
        assert [0x05, 0x00]==result

    def testFromBERNullKnownValues(self):
        """BERNull(encoded="...") should give known result with known input"""
        encoded=[0x05, 0x00]
        m=s(*encoded)
        result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
        self.assertEquals(bytes, len(m))
        assert isinstance(result, pureber.BERNull)
        assert 0x05==result.tag

    def testPartialBERNullEncodings(self):
        """BERNull(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m=str(pureber.BERNull())
        assert len(m)==2
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEquals((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))





class BERBooleanKnownValues(unittest.TestCase):
    knownValues=(
        (0, [0x01, 0x01, 0], 0),
        (1, [0x01, 0x01, 0xFF], 0xFF),
        (2, [0x01, 0x01, 0xFF], 0xFF),
        (125, [0x01, 0x01, 0xFF], 0xFF),
        (126, [0x01, 0x01, 0xFF], 0xFF),
        (127, [0x01, 0x01, 0xFF], 0xFF),
        (-1, [0x01, 0x01, 0xFF], 0xFF),
        (-2, [0x01, 0x01, 0xFF], 0xFF),
        (-3, [0x01, 0x01, 0xFF], 0xFF),
        (-126, [0x01, 0x01, 0xFF], 0xFF),
        (-127, [0x01, 0x01, 0xFF], 0xFF),
        (-128, [0x01, 0x01, 0xFF], 0xFF),
        (-129, [0x01, 0x01, 0xFF], 0xFF),
        (-9999, [0x01, 0x01, 0xFF], 0xFF),
        (128, [0x01, 0x01, 0xFF], 0xFF),
        (255, [0x01, 0x01, 0xFF], 0xFF),
        (256, [0x01, 0x01, 0xFF], 0xFF),
        (9999, [0x01, 0x01, 0xFF], 0xFF),
        )

    def testToBERBooleanKnownValues(self):
        """str(BERBoolean(n)) should give known result with known input"""
        for integer, encoded, dummy in self.knownValues:
            result = pureber.BERBoolean(integer)
            result = str(result)
            result = map(ord, result)
            assert encoded==result

    def testFromBERBooleanKnownValues(self):
        """BERBoolean(encoded="...") should give known result with known input"""
        for integer, encoded, canon in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEquals(bytes, len(m))
            assert isinstance(result, pureber.BERBoolean)
            result = result.value
            assert result==canon

    def testPartialBERBooleanEncodings(self):
        """BERBoolean(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m=str(pureber.BERBoolean(42))
        assert len(m)==3
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEquals((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))








class BEREnumeratedKnownValues(unittest.TestCase):
    knownValues=(
        (0, [0x0a, 0x01, 0]),
        (1, [0x0a, 0x01, 1]),
        (2, [0x0a, 0x01, 2]),
        (125, [0x0a, 0x01, 125]),
        (126, [0x0a, 0x01, 126]),
        (127, [0x0a, 0x01, 127]),
        (-1, [0x0a, 0x01, 256-1]),
        (-2, [0x0a, 0x01, 256-2]),
        (-3, [0x0a, 0x01, 256-3]),
        (-126, [0x0a, 0x01, 256-126]),
        (-127, [0x0a, 0x01, 256-127]),
        (-128, [0x0a, 0x01, 256-128]),
        (-129, [0x0a, 0x02, 256-1, 256-129]),
        (128, [0x0a, 0x02, 0, 128]),
        (256, [0x0a, 0x02, 1, 0]),
        )

    def testToBEREnumeratedKnownValues(self):
        """str(BEREnumerated(n)) should give known result with known input"""
        for integer, encoded in self.knownValues:
            result = pureber.BEREnumerated(integer)
            result = str(result)
            result = map(ord, result)
            assert encoded==result

    def testFromBEREnumeratedKnownValues(self):
        """BEREnumerated(encoded="...") should give known result with known input"""
        for integer, encoded in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEquals(bytes, len(m))
            assert isinstance(result, pureber.BEREnumerated)
            result = result.value
            assert integer==result

    def testPartialBEREnumeratedEncodings(self):
        """BEREnumerated(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m=str(pureber.BEREnumerated(42))
        assert len(m)==3
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEquals((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))


class BEREnumeratedSanityCheck(unittest.TestCase):
    def testSanity(self):
        """BEREnumerated(encoded=BEREnumerated(n)).value==n for -1000..1000"""
        for n in range(-1000, 1001, 10):
            encoded = str(pureber.BEREnumerated(n))
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), encoded)
            self.assertEquals(bytes, len(encoded))
            assert isinstance(result, pureber.BEREnumerated)
            result = result.value
            assert n==result


class BERSequenceKnownValues(unittest.TestCase):
    knownValues=(
        ([], [0x30, 0x00]),
        ([pureber.BERInteger(2)], [0x30, 0x03, 0x02, 0x01, 2]),
        ([pureber.BERInteger(3)], [0x30, 0x03, 0x02, 0x01, 3]),
        ([pureber.BERInteger(128)], [0x30, 0x04, 0x02, 0x02, 0, 128]),
        ([pureber.BERInteger(2), pureber.BERInteger(3), pureber.BERInteger(128)],
         [0x30, 0x0a]+[0x02, 0x01, 2]+[0x02, 0x01, 3]+[0x02, 0x02, 0, 128]),
        )

    def testToBERSequenceKnownValues(self):
        """str(BERSequence(x)) should give known result with known input"""
        for content, encoded in self.knownValues:
            result = pureber.BERSequence(content)
            result = str(result)
            result = map(ord, result)
            assert encoded==result

    def testFromBERSequenceKnownValues(self):
        """BERSequence(encoded="...") should give known result with known input"""
        for content, encoded in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEquals(bytes, len(m))
            assert isinstance(result, pureber.BERSequence)
            result = result.data
            assert len(content)==len(result)
            for i in xrange(len(content)):
                assert content[i]==result[i]
            assert content==result

    def testPartialBERSequenceEncodings(self):
        """BERSequence(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m=str(pureber.BERSequence([pureber.BERInteger(2)]))
        assert len(m)==5

        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:4])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:3])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEquals((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))

# TODO BERSequenceOf
# TODO BERSet
