"""
Test cases for ldaptor.protocols.ldap.ldapserver module.
"""

from twisted.trial import unittest
from ldaptor import inmemory
from ldaptor.protocols.ldap import ldapserver, ldaperrors, distinguishedname
from ldaptor.protocols import pureldap, pureber
from twisted.test import proto_helpers

class LDAPServerTest(unittest.TestCase):
    def setUp(self):
        root = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn='dc=example,dc=com',
            attributes={ 'dc': 'example',
                         })
        stuff = root.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('ou=stuff'),
            attributes={
            'objectClass': ['a', 'b'],
            'ou': ['stuff'],
            })
        thingie = stuff.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('cn=thingie'),
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['thingie'],
            })
        another = stuff.putChild(
            rdn=distinguishedname.RelativeDistinguishedName('cn=another'),
            attributes={
            'objectClass': ['a', 'b'],
            'cn': ['another'],
            })
        server = ldapserver.LDAPServer()
        server.factory = root
        server.transport = proto_helpers.StringTransport()
        server.connectionMade()
        self.server = server
    
    def test_bind(self):
        self.server.dataReceived(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=4)))

    def test_bind_invalidCredentials(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPBindRequest(dn='cn=non-existing,dc=example,dc=com',
                                     auth='invalid'),
            id=78))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPInvalidCredentials.resultCode,
            errorMessage='Authentication not yet supported (TODO)'),
            id=78)))

    def test_bind_badVersion_1_anonymous(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPBindRequest(version=1),
            id=32))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            errorMessage='Version 1 not supported'),
            id=32)))

    def test_bind_badVersion_2_anonymous(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPBindRequest(version=2),
            id=32))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            errorMessage='Version 2 not supported'),
            id=32)))

    def test_bind_badVersion_4_anonymous(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPBindRequest(version=4),
            id=32))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            errorMessage='Version 4 not supported'),
            id=32)))

    def test_bind_badVersion_4_nonExisting(self):
        # TODO make a test just like this one that would pass authentication
        # if version was correct, to ensure we don't leak that info either.
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPBindRequest(version=4,
                                     dn='cn=non-existing,dc=example,dc=com',
                                     auth='invalid'),
            id=11))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPBindResponse(
            resultCode=ldaperrors.LDAPProtocolError.resultCode,
            errorMessage='Version 4 not supported'),
            id=11)))

    def test_unbind(self):
        self.server.dataReceived(pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=7))
        self.assertEquals(self.server.transport.value(),
                          '')

    def test_search_outOfTree(self):
        self.server.dataReceived(str(pureldap.LDAPMessage(
            pureldap.LDAPSearchRequest(
            baseObject='dc=invalid',
            ), id=2)))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(resultCode=ldaperrors.LDAPNoSuchObject.resultCode),
            id=2)),
                          )

    def test_search_matchAll_oneResult(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPSearchRequest(
            baseObject='cn=thingie,ou=stuff,dc=example,dc=com',
            ), id=2))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='cn=thingie,ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('cn', ['thingie']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(resultCode=0),
            id=2)),
                          )

    def test_search_matchAll_manyResults(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPSearchRequest(
            baseObject='ou=stuff,dc=example,dc=com',
            ), id=2))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('ou', ['stuff']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='cn=another,ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('cn', ['another']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='cn=thingie,ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('cn', ['thingie']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(resultCode=0),
            id=2)),
                          )

    def test_search_scope_oneLevel(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPSearchRequest(
            baseObject='ou=stuff,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_singleLevel,
            ), id=2))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='cn=thingie,ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('cn', ['thingie']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='cn=another,ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('cn', ['another']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(resultCode=0),
            id=2)),
                          )

    def test_search_scope_wholeSubtree(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPSearchRequest(
            baseObject='ou=stuff,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_wholeSubtree,
            ), id=2))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('ou', ['stuff']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='cn=another,ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('cn', ['another']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='cn=thingie,ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('cn', ['thingie']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(resultCode=0),
            id=2)),
                          )

    def test_search_scope_baseObject(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPSearchRequest(
            baseObject='ou=stuff,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_baseObject,
            ), id=2))
        self.assertEquals(self.server.transport.value(),
                          str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry(
            objectName='ou=stuff,dc=example,dc=com',
            attributes=[ ('objectClass', ['a', 'b']),
                         ('ou', ['stuff']),
                         ]),
            id=2))
                          + str(pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(resultCode=0),
            id=2)),
                          )
