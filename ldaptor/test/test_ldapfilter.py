"""
Test cases for ldaptor.protocols.ldap.ldapfilter module.
"""

from twisted.trial import unittest
from ldaptor.mutablestring import MutableString
from ldaptor.protocols import pureldap, pureber
from ldaptor import ldapfilter
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

class LDAPFilter(unittest.TestCase):
    knownValues=( # args, kwargs, expected_result
	([],
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
	)

    def testToLDAPModifyRequestKnownValues(self):
	"""str(LDAPModifyRequest(...)) should give known result with known input"""
	for args, kwargs, encoded in self.knownValues:
	    result = pureldap.LDAPModifyRequest(*args, **kwargs)
	    result = str(result)
	    result = map(ord, result)
	    if encoded!=result:
		raise AssertionError(encoded, result)

    def testFromLDAPModifyRequestKnownValues(self):
	"""LDAPModifyRequest(encoded="...") should give known result with known input"""
	for args, kwargs, encoded in self.knownValues:
	    m=MutableString(s(*encoded))
	    m.append('foo')
	    result = pureldap.LDAPModifyRequest(encoded=m, berdecoder=pureber.BERDecoderContext())
	    assert m=='foo'
	    #TODO assert integer==result

    def testPartialLDAPModifyRequestEncodings(self):
	"""LDAPModifyRequest(encoded="...") with too short input should throw BERExceptionInsufficientData"""
	m=str(pureldap.LDAPModifyRequest(object='foo', modification=[pureldap.LDAPModification_delete(['bar'])]))
	for i in xrange(len(m)):
	    self.assertRaises(pureber.BERExceptionInsufficientData, pureldap.LDAPModifyRequest, encoded=m[:i], berdecoder=pureber.BERDecoderContext())
