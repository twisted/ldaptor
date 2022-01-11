"""
Test cases for ldaptor.protocols.ldap.fetchschema module.
"""

from twisted.trial import unittest
from ldaptor.protocols.ldap import fetchschema
from ldaptor import schema
from ldaptor.protocols import pureldap
from ldaptor.testutil import LDAPClientTestDriver
from ldaptor._encoder import to_bytes


class OnWire(unittest.TestCase):
    cn = """( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )"""
    dcObject = """( 1.3.6.1.4.1.1466.344 NAME 'dcObject' DESC 'RFC2247: domain component object' SUP top AUXILIARY MUST dc )"""

    def testSimple(self):
        client = LDAPClientTestDriver(
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="",
                    attributes=(
                        ("subschemaSubentry", ["cn=Subschema"]),
                        ("bar", ["b", "c"]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
            [
                pureldap.LDAPSearchResultEntry(
                    objectName="cn=Subschema",
                    attributes=(
                        ("attributeTypes", [self.cn]),
                        ("objectClasses", [self.dcObject]),
                    ),
                ),
                pureldap.LDAPSearchResultDone(
                    resultCode=0, matchedDN="", errorMessage=""
                ),
            ],
        )

        d = fetchschema.fetch(client, "dc=example,dc=com")
        d.addCallback(self._cb_testSimple, client)
        return d

    def _cb_testSimple(self, val, client):
        client.assertSent(
            pureldap.LDAPSearchRequest(
                baseObject="dc=example,dc=com",
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=1,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_present("objectClass"),
                attributes=["subschemaSubentry"],
            ),
            pureldap.LDAPSearchRequest(
                baseObject="cn=Subschema",
                scope=pureldap.LDAP_SCOPE_baseObject,
                derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
                sizeLimit=1,
                timeLimit=0,
                typesOnly=0,
                filter=pureldap.LDAPFilter_present("objectClass"),
                attributes=["attributeTypes", "objectClasses"],
            ),
        )
        self.assertEqual(len(val), 2)

        self.assertEqual(
            [to_bytes(x) for x in val[0]],
            [to_bytes(schema.AttributeTypeDescription(self.cn))],
        )
        self.assertEqual(
            [to_bytes(x) for x in val[1]],
            [to_bytes(schema.ObjectClassDescription(self.dcObject))],
        )
