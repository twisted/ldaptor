"""
Support for writing a set of directory entries as LDIF.
You probably want to use this only indirectly, as in
str(LDAPEntry(...)).

TODO support writing modify operations
TODO support reading modify operations

TODO implement rest of syntax from RFC2849

"""

# RFC2849: The LDAP Data Interchange Format (LDIF) - Technical Specification

import base64

import six

from ldaptor.encoder import to_bytes


def base64_encode(s):
    return b''.join(base64.encodestring(s).split(b'\n')) + b'\n'


def attributeAsLDIF_base64(attribute, value):
    return b'%s:: %s' % (attribute, base64_encode(value))


def containsNonprintable(s):
    for i in six.moves.xrange(len(s)):
        c = s[i:i + 1]
        if ord(c) > 127 or c == b'\0' or c == b'\n' or c == b'\r':
            return True
    return False


def attributeAsLDIF(attribute, value):
    attribute = to_bytes(attribute)
    value = to_bytes(value)
    if value.startswith(b'\0') \
       or value.startswith(b'\n') \
       or value.startswith(b'\r') \
       or value.startswith(b' ') \
       or value.startswith(b':') \
       or value.startswith(b'<') \
       or value.endswith(b' ') \
       or containsNonprintable(value):
        return attributeAsLDIF_base64(attribute, value)
    else:
        return b'%s: %s\n' % (attribute, value)


def asLDIF(dn, attributes):
    s = b'dn: %s\n' % to_bytes(dn)
    for k, vs in attributes:
        for v in vs:
            s = s + attributeAsLDIF(k, v)
    s = s + b'\n'
    return s


def header():
    return b'version: 1\n\n'


def manyAsLDIF(objects):
    s = [header()]
    for dn, attributes in objects:
        s.append(asLDIF(dn, attributes))
    return b''.join(s)
