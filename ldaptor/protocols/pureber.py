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

"""Pure, simple, BER encoding and decoding"""

# This BER library is currently aimed at supporting LDAP, thus
# the following restrictions from RFC2251 apply:
#
# (1) Only the definite form of length encoding will be used.
#
# (2) OCTET STRING values will be encoded in the primitive form
#     only.
#
# (3) If the value of a BOOLEAN type is true, the encoding MUST have
#     its contents octets set to hex "FF".
#
# (4) If a value of a type is its default value, it MUST be absent.
#     Only some BOOLEAN and INTEGER types have default values in
#     this protocol definition.
import warnings

import six

from ldaptor.encoder import to_bytes

# xxxxxxxx
# |/|\.../
# | | |
# | | tag
# | |
# | primitive (0) or structured (1)
# |
# class

CLASS_MASK = 0xc0
CLASS_UNIVERSAL = 0x00
CLASS_APPLICATION = 0x40
CLASS_CONTEXT = 0x80
CLASS_PRIVATE = 0xc0

STRUCTURED_MASK = 0x20
STRUCTURED = 0x20
NOT_STRUCTURED = 0x00

TAG_MASK = 0x1f


# LENGTH
# 0xxxxxxx = 0..127
# 1xxxxxxx = len is stored in the next 0xxxxxxx octets
# indefinite form not supported

class UnknownBERTag(Exception):
    def __init__(self, tag, context):
        Exception.__init__(self)
        self.tag = tag
        self.context = context

    def __str__(self):
        return "BERDecoderContext has no tag 0x%02x: %s" \
               % (self.tag, self.context)


def berDecodeLength(m, offset=0):
    """
    Return a tuple of (length, lengthLength).
    m must be atleast one byte long.
    """
    l = ber2int(m[offset + 0:offset + 1])
    ll = 1
    if l & 0x80:
        ll = 1 + (l & 0x7F)
        need(m, offset + ll)
        l = ber2int(m[offset + 1:offset + ll], signed=0)
    return (l, ll)


def int2berlen(i):
    assert i >= 0
    e = int2ber(i, signed=False)
    if i <= 127:
        return e
    else:
        l = len(e)
        assert l > 0
        assert l <= 127
        return six.int2byte(0x80 | l) + e


def int2ber(i, signed=True):
    encoded = b''
    while ((signed and (i > 127 or i < -128))
           or (not signed and (i > 255))):
        encoded = six.int2byte(i % 256) + encoded
        i = i >> 8
    encoded = six.int2byte(i % 256) + encoded
    return encoded


def ber2int(e, signed=True):
    need(e, 1)
    v = 0 + ord(e[0:1])
    if v & 0x80 and signed:
        v = v - 256
    for i in range(1, len(e)):
        v = (v << 8) | ord(e[i:i + 1])
    return v


class BERBase(object):
    tag = None

    def identification(self):
        return self.tag

    def __init__(self, tag=None):
        if tag is not None:
            self.tag = tag

    def __len__(self):
        return len(self.toWire())

    def __eq__(self, other):
        if not isinstance(other, BERBase):
            return NotImplemented
        return self.toWire() == other.toWire()

    def __ne__(self, other):
        if not isinstance(other, BERBase):
            return NotImplemented

        return self.toWire() != other.toWire()

    def __hash__(self):
        return hash(self.toWire())

    def toWire(self):
        return b''

    def __str__(self):
        warnings.simplefilter('always', DeprecationWarning)
        warnings.warn('{0}.__str__ method is deprecated and will not be used '
                      'for getting bytes representation in the future '
                      'releases, use {0}.toWire instead'.format(self.__class__.__name__),
                      category=DeprecationWarning)
        warnings.simplefilter('default', DeprecationWarning)
        return self.toWire()


class BERStructured(BERBase):
    def identification(self):
        return STRUCTURED | self.tag


class BERException(Exception): pass


class BERExceptionInsufficientData(Exception): pass


def need(buf, n):
    d = n - len(buf)
    if d > 0:
        raise BERExceptionInsufficientData(d)


class BERInteger(BERBase):
    tag = 0x02
    value = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        assert len(content) > 0
        value = ber2int(content)
        r = klass(value=value, tag=tag)
        return r

    def __init__(self, value=None, tag=None):
        """Create a new BERInteger object.
        value is an integer.
        """
        BERBase.__init__(self, tag)
        assert value is not None
        self.value = value

    def toWire(self):
        encoded = int2ber(self.value)
        return six.int2byte(self.identification()) \
               + int2berlen(len(encoded)) \
               + encoded

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%r)" % self.value
        else:
            return self.__class__.__name__ + "(value=%r, tag=%d)" \
                   % (self.value, self.tag)

class BEROctetString(BERBase):
    tag = 0x04

    value = None

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        assert len(content) >= 0
        r = klass(value=content, tag=tag)
        return r

    def __init__(self, value=None, tag=None):
        BERBase.__init__(self, tag)
        assert value is not None
        self.value = value

    def toWire(self):
        value = to_bytes(self.value)
        result = (
            six.int2byte(self.identification()) +
            int2berlen(len(value)) +
            value
            )
        return result

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" \
                   % repr(self.value)
        else:
            return self.__class__.__name__ \
                   + "(value=%s, tag=%d)" \
                     % (repr(self.value), self.tag)


class BERNull(BERBase):
    tag = 0x05

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        assert len(content) == 0
        r = klass(tag=tag)
        return r

    def __init__(self, tag=None):
        BERBase.__init__(self, tag)

    def toWire(self):
        return six.int2byte(self.identification()) + six.int2byte(0)

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "()"
        else:
            return self.__class__.__name__ + "(tag=%d)" % self.tag


class BERBoolean(BERBase):
    tag = 0x01

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        assert len(content) > 0
        value = ber2int(content)
        r = klass(value=value, tag=tag)
        return r

    def __init__(self, value=None, tag=None):
        """Create a new BERInteger object.
        value is an integer.
        """
        BERBase.__init__(self, tag)
        assert value is not None
        if value:
            value = 0xFF
        self.value = value

    def toWire(self):
        assert self.value == 0 or self.value == 0xFF
        return six.int2byte(self.identification()) \
               + int2berlen(1) \
               + six.int2byte(self.value)

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%d)" % self.value
        else:
            return self.__class__.__name__ + "(value=%d, tag=%d)" \
                   % (self.value, self.tag)


class BEREnumerated(BERInteger):
    tag = 0x0a


class BERSequence(BERStructured, six.moves.UserList):
    # TODO __getslice__ calls __init__ with no args.
    tag = 0x10

    @classmethod
    def fromBER(klass, tag, content, berdecoder=None):
        l = berDecodeMultiple(content, berdecoder)
        r = klass(l, tag=tag)
        return r

    def __init__(self, value=None, tag=None):
        BERStructured.__init__(self, tag)
        assert value is not None
        six.moves.UserList.__init__(self, value)

    def toWire(self):
        r = b''.join(to_bytes(x) for x in self.data)
        return six.int2byte(self.identification()) + int2berlen(len(r)) + r

    def __repr__(self):
        if self.tag == self.__class__.tag:
            return self.__class__.__name__ + "(value=%s)" % repr(self.data)
        else:
            return self.__class__.__name__ + "(value=%s, tag=%d)" \
                   % (repr(self.data), self.tag)


class BERSequenceOf(BERSequence):
    pass


class BERSet(BERSequence):
    tag = 0x11
    pass



class BERDecoderContext:
    Identities = {
        BERInteger.tag: BERInteger,
        BEROctetString.tag: BEROctetString,
        BERNull.tag: BERNull,
        BERBoolean.tag: BERBoolean,
        BEREnumerated.tag: BEREnumerated,
        BERSequence.tag: BERSequence,
        BERSet.tag: BERSet,
        }

    def __init__(self, fallback=None, inherit=None):
        self.fallback = fallback
        self.inherit_context = inherit

    def lookup_id(self, id):
        try:
            return self.Identities[id]
        except KeyError:
            if self.fallback:
                return self.fallback.lookup_id(id)
            else:
                return None

    def inherit(self):
        return self.inherit_context or self

    def __repr__(self):
        identities = []
        for tag, class_ in self.Identities.items():
            identities.append('0x%02x: %s' % (tag, class_.__name__))
        return "<"+self.__class__.__name__ \
               +" identities={%s}" % ', '.join(identities) \
               +" fallback="+repr(self.fallback) \
               +" inherit="+repr(self.inherit_context) \
               +">"

def berDecodeObject(context, m):
    """berDecodeObject(context, bytes) -> (berobject, bytesUsed)
    berobject may be None.
    """
    while m:
        need(m, 2)
        i = ber2int(m[0:1], signed=0) & (CLASS_MASK | TAG_MASK)

        length, lenlen = berDecodeLength(m, offset=1)
        need(m, 1 + lenlen + length)
        m2 = m[1 + lenlen:1 + lenlen + length]

        berclass = context.lookup_id(i)
        if berclass:
            inh = context.inherit()
            assert inh
            r = berclass.fromBER(tag=i,
                                 content=m2,
                                 berdecoder=inh)
            return (r, 1 + lenlen + length)
        else:
            print(str(UnknownBERTag(i, context)))  # TODO
            return (None, 1 + lenlen + length)
    return (None, 0)


def berDecodeMultiple(content, berdecoder):
    """berDecodeMultiple(content, berdecoder) -> [objects]

    Decodes everything in content and returns a list of decoded
    objects.

    All of content will be decoded, and content must contain complete
    BER objects.
    """
    l = []
    while content:
        n, bytes = berDecodeObject(berdecoder, content)
        if n is not None:
            l.append(n)
        assert bytes <= len(content)
        content = content[bytes:]
    return l

# TODO unimplemented classes are below:

# class BERObjectIdentifier(BERBase):
#    tag = 0x06
#    pass

# class BERIA5String(BERBase):
#    tag = 0x16
#    pass

# class BERPrintableString(BERBase):
#    tag = 0x13
#    pass

# class BERT61String(BERBase):
#    tag = 0x14
#    pass

# class BERUTCTime(BERBase):
#    tag = 0x17
#    pass

# class BERBitString(BERBase):
#    tag = 0x03
#    pass
