"""
Test cases for ldaptor.protocols.ldap.fetchschema module.
"""

from twisted.trial import unittest
from ldaptor.protocols.ldap import ldapsyntax, fetchschema
from ldaptor import schema
from ldaptor.protocols import pureldap, pureber
from twisted.internet import defer
from twisted.python import failure
from ldaptor.testutil import LDAPClientTestDriver
from twisted.trial.util import deferredResult

class OnWire(unittest.TestCase):
    cn = """( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )"""
    dcObject = """( 1.3.6.1.4.1.1466.344 NAME 'dcObject' DESC 'RFC2247: domain component object' SUP top AUXILIARY MUST dc )"""

    def testSimple(self):
	client=LDAPClientTestDriver([
            pureldap.LDAPSearchResultEntry(
            objectName='',
            attributes=(('subschemaSubentry', ['cn=Subschema']),
                        ('bar', ['b', 'c']),
                        ),
            ),
            pureldap.LDAPSearchResultDone(
            resultCode=0,
            matchedDN='',
            errorMessage='')
            ],
                                    [
            pureldap.LDAPSearchResultEntry(
            objectName='cn=Subschema',
            attributes=(('attributeTypes', [ self.cn ]),
                        ('objectClasses', [ self.dcObject ]),
                        ),
            ),
            pureldap.LDAPSearchResultDone(
            resultCode=0,
            matchedDN='',
            errorMessage='')
            ],
                                    )

        d=fetchschema.fetch(client, 'dc=example,dc=com')
        val = deferredResult(d)

	client.assertSent(pureldap.LDAPSearchRequest(
	    baseObject='dc=example,dc=com',
	    scope=pureldap.LDAP_SCOPE_baseObject,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=1,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_present('objectClass'),
	    attributes=['subschemaSubentry']),
                          pureldap.LDAPSearchRequest(
	    baseObject='cn=Subschema',
	    scope=pureldap.LDAP_SCOPE_baseObject,
	    derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	    sizeLimit=1,
	    timeLimit=0,
	    typesOnly=0,
	    filter=pureldap.LDAPFilter_present('objectClass'),
	    attributes=['attributeTypes', 'objectClasses']),
                          )
	self.failUnlessEqual(len(val), 2)

	self.failUnlessEqual([str(x) for x in val[0]],
                             [str(schema.AttributeTypeDescription(self.cn))])
	self.failUnlessEqual([str(x) for x in val[1]],
                             [str(schema.ObjectClassDescription(self.dcObject))])
