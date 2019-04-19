from functools import total_ordering

import six

from ldaptor._encoder import to_unicode, TextStrAlias

# See rfc2253
# Note that RFC 2253 sections 2.4 and 3 disagree whether "=" needs to
# be quoted. Let's trust the syntax, slapd refuses to accept unescaped
# "=" in RDN values.
escapedChars = u',+"\<>;='
escapedChars_leading = u' #'
escapedChars_trailing = u' #'


def escape(s):
    r = u''
    r_trailer = u''

    if s and s[0] in escapedChars_leading:
        r = u'\\' + s[0]
        s = s[1:]

    if s and s[-1] in escapedChars_trailing:
        r_trailer = u'\\' + s[-1]
        s = s[:-1]

    for c in s:
        if c in escapedChars:
            r = r + u'\\' + c
        elif ord(c) <= 31:
            r = r + u'\\%02X' % ord(c)
        else:
            r = r + c

    return r + r_trailer


def unescape(s):
    r = u''

    while s:
        if s[0] == u'\\':
            if s[1] in u'0123456789abcdef':
                r = r + chr(int(s[1:3], 16))
                s = s[3:]
            else:
                r = r + s[1]
                s = s[2:]
        else:
            r = r + s[0]
            s = s[1:]

    return r


def _splitOnNotEscaped(s, separator):
    if not s:
        return []

    r = [u'']
    while s:
        first = s[0:1]

        if first == u'\\':
            r[-1] = r[-1] + s[:2]
            s = s[2:]
        else:

            if first == separator:
                r.append(u'')
                s = s[1:]
                while s[0:1] == u' ':
                    s = s[1:]
            else:
                r[-1] = r[-1] + first
                s = s[1:]

    return r


class InvalidRelativeDistinguishedName(Exception):
    """
    Invalid relative distinguished name.
    It is assumed that passed RDN is of str type:
    bytes for PY2 and unicode for PY3.
    """

    def __init__(self, rdn):
        Exception.__init__(self)
        self.rdn = rdn.encode('utf-8') if six.PY2 else rdn

    def __str__(self):
        return "Invalid relative distinguished name %s." \
               % repr(self.rdn)


class LDAPAttributeTypeAndValue(TextStrAlias):
    # TODO I should be used everywhere
    attributeType = None
    value = None

    def __init__(self, stringValue=None, attributeType=None, value=None):
        if stringValue is None:
            assert attributeType is not None
            assert value is not None
            self.attributeType = to_unicode(attributeType)
            self.value = to_unicode(value)
        else:
            assert attributeType is None
            assert value is None

            stringValue = to_unicode(stringValue)

            if u'=' not in stringValue:
                raise InvalidRelativeDistinguishedName(stringValue)
            self.attributeType, self.value = stringValue.split(u'=', 1)

    def getText(self):
        return u'='.join((escape(self.attributeType), escape(self.value)))

    def __repr__(self):
        return (self.__class__.__name__
                + '(attributeType='
                + repr(self.attributeType)
                + ', value='
                + repr(self.value)
                + ')')

    def __hash__(self):
        return hash((self.attributeType, self.value))

    def __eq__(self, other):
        if not isinstance(other, LDAPAttributeTypeAndValue):
            return NotImplemented
        return (self.attributeType.lower() == other.attributeType.lower()
                and self.value.lower() == other.value.lower())

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if self.attributeType != other.attributeType:
            return self.attributeType < other.attributeType
        else:
            return self.value < other.value

    def __gt__(self, other):
        return (self != other
                and self > other)

    def __le__(self, other):
        return not self > other

    def __ge__(self, other):
        return not self < other


class RelativeDistinguishedName(TextStrAlias):
    """LDAP Relative Distinguished Name."""

    attributeTypesAndValues = None

    def __init__(self, magic=None, stringValue=None, attributeTypesAndValues=None):
        if magic is not None:
            assert stringValue is None
            assert attributeTypesAndValues is None
            if isinstance(magic, RelativeDistinguishedName):
                attributeTypesAndValues = magic.split()
            elif isinstance(magic, (six.binary_type, six.text_type)):
                stringValue = magic
            else:
                attributeTypesAndValues = magic

        if stringValue is None:
            assert attributeTypesAndValues is not None
            assert not isinstance(attributeTypesAndValues, (six.binary_type, six.text_type))
            self.attributeTypesAndValues = tuple(attributeTypesAndValues)
        else:
            assert attributeTypesAndValues is None
            self.attributeTypesAndValues = tuple([LDAPAttributeTypeAndValue(stringValue=unescape(x))
                                                  for x in _splitOnNotEscaped(to_unicode(stringValue), u'+')])

    def split(self):
        return self.attributeTypesAndValues

    def getText(self):
        return u'+'.join([x.getText() for x in self.attributeTypesAndValues])

    def __repr__(self):
        return (self.__class__.__name__
                + '(attributeTypesAndValues='
                + repr(self.attributeTypesAndValues)
                + ')')

    def __hash__(self):
        return hash(self.attributeTypesAndValues)

    def __eq__(self, other):
        if not isinstance(other, RelativeDistinguishedName):
            return NotImplemented
        return self.split() == other.split()

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.split() < other.split()

    def __gt__(self, other):
        return (self != other
                and self >= other)

    def __le__(self, other):
        return not self > other

    def __ge__(self, other):
        return not self < other

    def count(self):
        return len(self.attributeTypesAndValues)


@total_ordering
class DistinguishedName(TextStrAlias):
    """LDAP Distinguished Name."""
    listOfRDNs = None

    def __init__(self, magic=None, stringValue=None, listOfRDNs=None):
        assert (magic is not None
                or stringValue is not None
                or listOfRDNs is not None)
        if magic is not None:
            assert stringValue is None
            assert listOfRDNs is None
            if isinstance(magic, DistinguishedName):
                listOfRDNs = magic.split()
            elif isinstance(magic, (six.binary_type, six.text_type)):
                # This might need to be expended if we want to support
                # different encodings.
                stringValue = magic
            else:
                listOfRDNs = magic

        if stringValue is None:
            assert listOfRDNs is not None
            for x in listOfRDNs:
                assert isinstance(x, RelativeDistinguishedName)
            self.listOfRDNs = tuple(listOfRDNs)
        else:
            assert listOfRDNs is None
            self.listOfRDNs = tuple([RelativeDistinguishedName(stringValue=x)
                                     for x in _splitOnNotEscaped(to_unicode(stringValue), u',')])

    def split(self):
        return self.listOfRDNs

    def up(self):
        return DistinguishedName(listOfRDNs=self.listOfRDNs[1:])

    def getText(self):
        return u','.join([x.getText() for x in self.listOfRDNs])

    def __repr__(self):
        return (self.__class__.__name__
                + '(listOfRDNs='
                + repr(self.listOfRDNs)
                + ')')

    def __hash__(self):
        return hash(self.getText())

    def __eq__(self, other):
        if isinstance(other, six.binary_type):
            return self.getText().encode('utf-8') == other
        if isinstance(other, six.text_type):
            return self.getText() == other
        if not isinstance(other, DistinguishedName):
            return NotImplemented
        return self.split() == other.split()

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        """
        Comparison used for determining the hierarchy.
        """
        if not isinstance(other, DistinguishedName):
            return NotImplemented

        # The comparison is naive and broken.
        # See https://github.com/twisted/ldaptor/issues/94
        return self.split() < other.split()


    def getDomainName(self):
        domainParts = []
        l = list(self.listOfRDNs)
        l.reverse()
        for rdn in l:
            if rdn.count() != 1:
                break
            attributeTypeAndValue = rdn.split()[0]
            if attributeTypeAndValue.attributeType.upper() != u'DC':
                break
            domainParts.insert(0, attributeTypeAndValue.value)
        if domainParts:
            return u'.'.join(domainParts)
        else:
            return None

    def contains(self, other):
        """Does the tree rooted at DN contain or equal the other DN."""
        if self == other:
            return 1
        if not isinstance(other, DistinguishedName):
            other = DistinguishedName(other)
        its = list(other.split())
        mine = list(self.split())

        while mine and its:
            m = mine.pop()
            i = its.pop()
            if m != i:
                return 0
        if mine:
            return 0
        return 1
