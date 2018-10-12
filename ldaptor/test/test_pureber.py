# Copyright (C) 2001 Tommi Virtanen
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
import six
from twisted.trial import unittest

from ldaptor.protocols import pureber


def s(*l):
    """Join all members of list to a byte string. Integer members are converted to bytes"""
    r = b''
    for e in l:
        e = six.int2byte(e)
        r = r + e
    return r


def l(s):
    """Split a byte string to ord's of chars."""
    return [six.byte2int([x]) for x in s]


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
            got = bytes(got)
            got = l(got)
            self.assertEqual(got, encoded)

    def testFromBER(self):
        for integer, encoded in self.knownValues:
            m=s(*encoded)
            got, bytes = pureber.berDecodeLength(m)
            self.assertEqual(bytes, len(m))
            self.assertEqual(got, integer)

    def testPartialBER(self):
        m = bytes(pureber.int2berlen(3*256))
        self.assertEqual(3, len(m))
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeLength, m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeLength, m[:1])

        m = bytes(pureber.int2berlen(256**100-1))
        self.assertEqual(101, len(m))
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeLength, m[:100])


class BERBaseTests(unittest.TestCase):
    """
    Unit tests for generic BERBase.
    """
    valuesToTest=(
        (pureber.BERBase, []),
        (pureber.BERInteger, [0]),
        (pureber.BERInteger, [1]),
        (pureber.BERInteger, [4000]),
        (pureber.BERSequence, [[pureber.BERInteger(1000), pureber.BERInteger(2000)]]),
        (pureber.BERSequence, [[pureber.BERInteger(2000), pureber.BERInteger(1000)]]),
        (pureber.BEROctetString, ["foo"]),
        (pureber.BEROctetString, ["b"+chr(0xe4)+chr(0xe4)]),
        )

    def testEquality(self):
        """
        BER objects equal BER objects with same type and content
        """
        for class_, args in self.valuesToTest:
            x=class_(*args)
            y=class_(*args)
            self.assertEqual(x, x)
            self.assertEqual(x, y)

    def testInequalityWithBER(self):
        """
        BER objects do not equal BER objects with different type or content
        """
        for i in six.moves.range(len(self.valuesToTest)):
            for j in six.moves.range(len(self.valuesToTest)):
                if i!=j:
                    i_class, i_args = self.valuesToTest[i]
                    j_class, j_args = self.valuesToTest[j]
                    x=i_class(*i_args)
                    y=j_class(*j_args)
                    self.assertNotEqual(x, y)

    def testInequalityWithNonBER(self):
        """
        BER objects are not equal with non-BER objects.
        """
        sut = pureber.BERInteger([0])

        self.assertFalse(0 == sut)
        self.assertNotEqual(0, sut)

    def testHashEquality(self):
        """
        Objects which are equal have the same hash.
        """
        for klass, arguments in self.valuesToTest:
            first = klass(*arguments)
            second = klass(*arguments)
            self.assertEqual(hash(first), hash(second))


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
        """BERInteger(n).toWire() should give known result with known input"""
        for integer, encoded in self.knownValues:
            result = pureber.BERInteger(integer)
            result = result.toWire()
            result = l(result)
            self.assertEqual(encoded, result)

    def testFromBERIntegerKnownValues(self):
        """BERInteger(encoded="...") should give known result with known input"""
        for integer, encoded in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEqual(bytes, len(m))
            self.assertIsInstance(result, pureber.BERInteger)
            result = result.value
            self.assertEqual(integer, result)

    def testPartialBERIntegerEncodings(self):
        """BERInteger(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BERInteger(42).toWire()
        self.assertEqual(3, len(m))
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEqual((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))


class BERIntegerSanityCheck(unittest.TestCase):
    def testSanity(self):
        """BERInteger(encoded=BERInteger(n)).value==n for -1000..1000"""
        for n in range(-1000, 1001, 10):
            encoded = pureber.BERInteger(n).toWire()
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), encoded)
            self.assertEqual(bytes, len(encoded))
            self.assertIsInstance(result, pureber.BERInteger)
            result = result.value
            self.assertEqual(n, result)


class ObjectWithToWireMethod(object):
    def toWire(self):
        return b"bar"


class TestBEROctetString(unittest.TestCase):
    """
    Unit tests for BEROctetString.
    """
    knownValues=(
        ("", [0x04, 0]),
        ("foo", [0x04, 3]+l(b"foo")),
        (100 * "x", [0x04, 100]+l(100 * b"x")),
        (ObjectWithToWireMethod(), [0x04, 3]+l(b"bar")),
        )

    def testToBEROctetStringKnownValues(self):
        """BEROctetString(n).toWire() should give known result with known input"""
        for st, encoded in self.knownValues:
            result = pureber.BEROctetString(st)
            result = result.toWire()
            result = l(result)
            self.assertEqual(encoded, result)

    def testFromBEROctetStringKnownValues(self):
        """BEROctetString(encoded="...") should give known result with known input"""
        for st, encoded in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEqual(bytes, len(m))
            self.assertIsInstance(result, pureber.BEROctetString)
            result = result.toWire()
            result = l(result)
            self.assertEqual(encoded, result)

    def testPartialBEROctetStringEncodings(self):
        """BEROctetString(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BEROctetString("x").toWire()
        self.assertEqual(3, len(m))
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEqual((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))

    def testSanity(self):
        """BEROctetString(encoded=BEROctetString(n*'x')).value==n*'x' for some values of n"""
        for n in 0,1,2,3,4,5,6,100,126,127,128,129,1000,2000:
            encoded = pureber.BEROctetString(n * b'x').toWire()
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), encoded)
            self.assertEqual(bytes, len(encoded))
            self.assertIsInstance(result, pureber.BEROctetString)
            result = result.value
            self.assertEqual(n * b'x', result)


class BERNullKnownValues(unittest.TestCase):
    def testToBERNullKnownValues(self):
        """BERNull().toWire() should give known result"""
        result = pureber.BERNull()
        result = result.toWire()
        result = l(result)
        self.assertEqual([0x05, 0x00], result)

    def testFromBERNullKnownValues(self):
        """BERNull(encoded="...") should give known result with known input"""
        encoded=[0x05, 0x00]
        m=s(*encoded)
        result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
        self.assertEqual(bytes, len(m))
        self.assertIsInstance(result, pureber.BERNull)
        self.assertEqual(0x05, result.tag)

    def testPartialBERNullEncodings(self):
        """BERNull(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BERNull().toWire()
        self.assertEqual(2, len(m))
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEqual((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))


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
        """BERBoolean(n).toWire() should give known result with known input"""
        for integer, encoded, dummy in self.knownValues:
            result = pureber.BERBoolean(integer)
            result = result.toWire()
            result = l(result)
            self.assertEqual(encoded, result)

    def testFromBERBooleanKnownValues(self):
        """BERBoolean(encoded="...") should give known result with known input"""
        for integer, encoded, canon in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEqual(bytes, len(m))
            self.assertIsInstance(result, pureber.BERBoolean)
            result = result.value
            self.assertEqual(canon, result)

    def testPartialBERBooleanEncodings(self):
        """BERBoolean(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BERBoolean(42).toWire()
        self.assertEqual(3, len(m))
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEqual((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))


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
        """BEREnumerated(n).toWire() should give known result with known input"""
        for integer, encoded in self.knownValues:
            result = pureber.BEREnumerated(integer)
            result = result.toWire()
            result = l(result)
            self.assertEqual(encoded, result)

    def testFromBEREnumeratedKnownValues(self):
        """BEREnumerated(encoded="...") should give known result with known input"""
        for integer, encoded in self.knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEqual(bytes, len(m))
            self.assertIsInstance(result, pureber.BEREnumerated)
            result = result.value
            self.assertEqual(integer, result)

    def testPartialBEREnumeratedEncodings(self):
        """BEREnumerated(encoded="...") with too short input should throw BERExceptionInsufficientData"""
        m = pureber.BEREnumerated(42).toWire()
        self.assertEqual(3, len(m))
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEqual((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))


class BEREnumeratedSanityCheck(unittest.TestCase):
    def testSanity(self):
        """BEREnumerated(encoded=BEREnumerated(n)).value==n for -1000..1000"""
        for n in range(-1000, 1001, 10):
            encoded = pureber.BEREnumerated(n).toWire()
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), encoded)
            self.assertEqual(bytes, len(encoded))
            self.assertIsInstance(result, pureber.BEREnumerated)
            result = result.value
            self.assertEqual(n, result)


class TestBERSequence(unittest.TestCase):
    """
    Unit test for BERSequence.
    """

    def testStringRepresentationEmpty(self):
        """
        It can return the byte string representation for empty sequence which
        is just the zero/null byte.
        """
        sut = pureber.BERSequence([])

        result = sut.toWire()

        self.assertEqual(b'0\x00', result)

    def testStringRepresentatinSmallInteger(self):
        """
        It can represent a sequence of a single integer which has a
        single byte value.
        """
        sut = pureber.BERSequence([pureber.BERInteger(2)])

        result = sut.toWire()

        self.assertEqual(b'0\x03\x02\x01\x02', result)

    def testStringRepresentatinLargerInteger(self):
        """
        It can represent a sequence of a single integer which has a
        multi bites value.
        """
        sut = pureber.BERSequence([pureber.BERInteger(128)])

        result = sut.toWire()

        self.assertEqual(b'0\x04\x02\x02\x00\x80', result)

    def testStringRepresentatinMultipleIntegers(self):
        """
        It can represent a sequence of multiple integer.
        """
        sut = pureber.BERSequence([
            pureber.BERInteger(3), pureber.BERInteger(128)])

        result = sut.toWire()

        self.assertEqual(b'0\x07\x02\x01\x03\x02\x02\x00\x80', result)

    def testDecodeValidInput(self):
        """
        It can be decoded from its bytes serialization.
        """
        knownValues=(
            ([], [0x30, 0x00]),
            ([pureber.BERInteger(2)], [0x30, 0x03, 0x02, 0x01, 2]),
            ([pureber.BERInteger(3)], [0x30, 0x03, 0x02, 0x01, 3]),
            ([pureber.BERInteger(128)], [0x30, 0x04, 0x02, 0x02, 0, 128]),
            ([
                pureber.BERInteger(2),
                pureber.BERInteger(3),
                pureber.BERInteger(128),
                ],
             [0x30, 0x0a] + [0x02, 0x01, 2] + [0x02, 0x01, 3] + [0x02, 0x02, 0, 128]),
            )

        for content, encoded in knownValues:
            m=s(*encoded)
            result, bytes = pureber.berDecodeObject(pureber.BERDecoderContext(), m)
            self.assertEqual(bytes, len(m))
            self.assertIsInstance(result, pureber.BERSequence)
            result = result.data
            self.assertEqual(len(content), len(result))
            for i in six.moves.range(len(content)):
                self.assertEqual(content[i], result[i])
            self.assertEqual(content, result)

    def testDecdeInvalidInput(self):
        """
        It raises BERExceptionInsufficientData when trying to decode from
        data which is not valid.
        """
        m = pureber.BERSequence([pureber.BERInteger(2)]).toWire()
        self.assertEqual(5, len(m))

        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:4])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:3])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:2])
        self.assertRaises(pureber.BERExceptionInsufficientData, pureber.berDecodeObject, pureber.BERDecoderContext(), m[:1])
        self.assertEqual((None, 0), pureber.berDecodeObject(pureber.BERDecoderContext(), ''))
