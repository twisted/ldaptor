"""
Support for writing a set of directory entries as LDIF.

TODO support reading directory entries
TODO support writing modify operations
TODO support reading modify operations

TODO implement rest of syntax from RFC2849

"""

# RFC2849: The LDAP Data Interchange Format (LDIF) - Technical Specification

import base64, string

def base64_encode(s):
    return ''.join(base64.encodestring(s).split('\n'))+'\n'

def attributeAsLDIF_base64(attribute, value):
    return "%s:: %s" % (attribute, base64_encode(value))

def containsNonprintable(s):
    for c in s:
        if ord(c) > 127 or c in ('\0', '\n', '\r'):
            return 1
    return 0

def attributeAsLDIF(attribute, value):
    if value.startswith('\0') \
       or value.startswith('\n') \
       or value.startswith('\r') \
       or value.startswith(' ') \
       or value.startswith(':') \
       or value.startswith('<') \
       or value.endswith(' ') \
       or containsNonprintable(value):
        return attributeAsLDIF_base64(attribute, value)
    else:
        return "%s: %s\n" % (attribute, value)

def asLDIF(dn, attributes):
    s="dn: %s\n"%dn
    for k,vs in attributes:
        for v in vs:
            s=s+attributeAsLDIF(k, v)
    s=s+"\n"
    return s

def header():
    return "version: 1\n\n"

def manyAsLDIF(objects):
    s=[header()]
    for dn, attributes in objects:
        s.append(asLDIF(dn, attributes))
    return ''.join(s)
