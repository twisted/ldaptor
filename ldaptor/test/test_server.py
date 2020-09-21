"""
Test cases for ldaptor.protocols.ldap.ldapserver module.
"""
import base64
import types

from twisted.internet import address, protocol
from twisted.python import components
from twisted.test import proto_helpers
from twisted.trial import unittest

from ldaptor import inmemory, interfaces, schema, delta, entry
from ldaptor.protocols.ldap import ldapserver, ldapclient, ldaperrors, \
    fetchschema
from ldaptor.protocols import pureldap, pureber
from ldaptor.test import util, test_schema
from ldaptor._encoder import to_bytes


def wrapCommit(entry, cb, *args, **kwds):
    bound_commit = entry.commit

    def commit_(self):
        d = bound_commit()
        d.addCallback(cb, *args, **kwds)
        return d

    f = types.MethodType(commit_, entry)
    entry.commit = f


class LDAPServerTest(unittest.TestCase):

    def setUp(self):
        self.root = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn='dc=example,dc=com',
            attributes={'dc': 'example'})
        self.stuff = self.root.addChild(
            rdn='ou=stuff',
            attributes={
                b'objectClass': [b'a', b'b'],
                b'ou': [b'stuff'],
            })
        self.thingie = self.stuff.addChild(
            rdn='cn=thingie',
            attributes={
                'objectClass': ['a', 'b'],
                'cn': ['thingie'],
            })
        self.another = self.stuff.addChild(
            rdn='cn=another',
            attributes={
                'objectClass': ['a', 'b'],
                'cn': ['another'],
            })

        # Add Users Subtree
        self.users = self.root.addChild(
            rdn='ou=People',
            attributes={
                'objectClass': ['top', 'organizationalunit'],
                'ou': ['People']
            })

        self.users.addChild(
            rdn='uid=kthompson',
            attributes={
                'objectClass': ['top', 'inetOrgPerson'],
                'uid': ['kthompson']
            })

        self.users.addChild(
            rdn='uid=bgates',
            attributes={
                'objectClass': ['top', 'inetOrgPerson'],
                'uid': ['bgates']
            })

        # Add Groups Subtree
        self.groups = self.root.addChild(
            rdn='ou=Groups',
            attributes={
                'objectClass': ['top', 'organizationalunit'],
                'ou': ['Groups']
            })

        self.groups.addChild(
            rdn='cn=unix',
            attributes={
                'uniquemember': ['uid=kthompson,ou=People,dc=example,dc=com'],
                'objectClass': ['top', 'groupOfUniqueNames'],
                'cn': ['unix']
            })

        server = ldapserver.LDAPServer()
        server.factory = self.root
        server.transport = proto_helpers.StringTransport()
        server.connectionMade()
        self.server = server

    def _makeResultList(self, s):
        berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
            inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
                fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
                inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())))
        buffer = s
        value = []
        while 1:
            o, bytes = pureber.berDecodeObject(berdecoder, buffer)
            buffer = buffer[bytes:]
            if not o:
                break
            value.append(o.toWire())
        return value

    def makeSearch(self, baseObject=None, scope=None, derefAliases=None,
                    sizeLimit=None, timeLimit=None, typesOnly=None,
                    filter=None, attributes=None, tag=None):
        """Shortcut for sending LDAPSearchRequest to the test server"""
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchRequest(baseObject=baseObject, scope=scope, derefAliases=derefAliases,
                                           sizeLimit=sizeLimit, timeLimit=timeLimit, typesOnly=typesOnly,
                                           filter=filter, attributes=attributes, tag=tag),
                id=2,
            ).toWire()
        )

    def assertSearchResults(self, results=None, resultCode=0):
        """
        Shortcut for checking results returned by test server on LDAPSearchRequest.
        Results must be prepared as a list of dictionaries with 'objectName' and 'attributes' keys
        """
        if results is None:
            results = []

        messages = []

        for result in results:
            message = pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(
                    objectName=result['objectName'],
                    attributes=result['attributes']
                ),
                id=2
            )
            messages.append(message)

        messages.append(
            pureldap.LDAPMessage(
                pureldap.LDAPSearchResultDone(resultCode=resultCode),
                id=2
            )
        )
        self.assertCountEqual(
            self._makeResultList(self.server.transport.value()),
            [msg.toWire() for msg in messages]
        )

    def test_bind(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0),
                id=4).toWire())

    def test_bind_success(self):
        self.thingie['userPassword'] = ['{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8=']  # "secret"
        self.server.dataReceived(
                pureldap.LDAPMessage(
                    pureldap.LDAPBindRequest(
                        dn='cn=thingie,ou=stuff,dc=example,dc=com',
                        auth=b'secret'),
                    id=4).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0,
                    matchedDN='cn=thingie,ou=stuff,dc=example,dc=com'),
                id=4).toWire())

    def test_bind_invalidCredentials_badPassword(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn='cn=thingie,ou=stuff,dc=example,dc=com',
                    auth=b'invalid'),
                id=734).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPInvalidCredentials.resultCode),
                id=734).toWire())

    def test_bind_invalidCredentials_nonExisting(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn='cn=non-existing,dc=example,dc=com',
                    auth=b'invalid'),
                id=78).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPInvalidCredentials.resultCode),
                id=78).toWire())

    def test_bind_badVersion_1_anonymous(self):
        self.server.dataReceived(
                pureldap.LDAPMessage(
                    pureldap.LDAPBindRequest(version=1),
                    id=32).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage='Version 1 not supported'),
                id=32).toWire())

    def test_bind_badVersion_2_anonymous(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(version=2),
                id=32).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage='Version 2 not supported'),
                id=32).toWire())

    def test_bind_badVersion_4_anonymous(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(version=4),
                id=32).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage='Version 4 not supported'),
                id=32).toWire())

    def test_bind_badVersion_4_nonExisting(self):
        # TODO make a test just like this one that would pass authentication
        # if version was correct, to ensure we don't leak that info either.
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    version=4,
                    dn='cn=non-existing,dc=example,dc=com',
                    auth=b'invalid'),
                id=11).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage='Version 4 not supported'),
                id=11).toWire())

    def test_unbind(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=7).toWire())
        self.assertEqual(self.server.transport.value(), b'')

    def test_compare_outOfTree(self):
        dn = 'dc=invalid'
        attribute_desc = pureldap.LDAPString('objectClass')
        attribute_value = pureldap.LDAPString('groupOfUniqueNames')
        ava = pureldap.LDAPAttributeValueAssertion(attribute_desc, attribute_value)

        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPCompareRequest(entry=dn, ava=ava),
                id=2).toWire())

        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPCompareResponse(
                    resultCode=ldaperrors.LDAPNoSuchObject.resultCode),
                id=2).toWire())

    def test_compare_inGroup(self):
        dn = 'cn=unix,ou=Groups,dc=example,dc=com'
        attribute_desc = pureldap.LDAPString('uniquemember')
        attribute_value = pureldap.LDAPString('uid=kthompson,ou=People,dc=example,dc=com')
        ava = pureldap.LDAPAttributeValueAssertion(attribute_desc, attribute_value)

        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPCompareRequest(entry=dn, ava=ava),
                id=2).toWire())

        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPCompareResponse(
                    resultCode=ldaperrors.LDAPCompareTrue.resultCode),
                id=2).toWire())

    def test_compare_notInGroup(self):
        dn = 'cn=unix,ou=Groups,dc=example,dc=com'
        attribute_desc = pureldap.LDAPString('uniquemember')
        attribute_value = pureldap.LDAPString('uid=bgates,ou=People,dc=example,dc=com')
        ava = pureldap.LDAPAttributeValueAssertion(attribute_desc, attribute_value)

        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPCompareRequest(entry=dn, ava=ava),
                id=2).toWire())

        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPCompareResponse(
                    resultCode=ldaperrors.LDAPCompareFalse.resultCode),
                id=2).toWire())

    def test_search_outOfTree(self):
        """Attempt to get nonexistent DN results in noSuchObject error response"""
        self.makeSearch(baseObject='dc=invalid')
        self.assertSearchResults(resultCode=ldaperrors.LDAPNoSuchObject.resultCode)

    def test_search_matchAll_oneResult(self):
        """Searching for a single object with receiving all its attributes"""
        self.makeSearch(baseObject='cn=thingie,ou=stuff,dc=example,dc=com')
        self.assertSearchResults([
            {
                'objectName': 'cn=thingie,ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('cn', ['thingie']),
                ]
            }
        ])

    def test_search_matchAll_oneResult_filtered(self):
        """Searching for a single object with receiving a specified set of its attributes"""
        self.makeSearch(
            baseObject='cn=thingie,ou=stuff,dc=example,dc=com',
            attributes=['cn']
        )
        self.assertSearchResults([
            {
                'objectName': 'cn=thingie,ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('cn', ['thingie']),
                ]
            }
        ])

    def test_search_matchAll_oneResult_filteredNoAttribsRemaining(self):
        """
        Attempt to search an existing object with a set of nonexistent attributes
        results in a successful response with no attributes
        """
        self.makeSearch(
            baseObject='cn=thingie,ou=stuff,dc=example,dc=com',
            attributes=['xyzzy']
        )
        self.assertSearchResults(
            [
                {
                    'objectName': 'cn=thingie,ou=stuff,dc=example,dc=com',
                    'attributes': [],
                },
            ],
        )

    def test_search_matchAll_manyResults(self):
        """Searching for a tree object with receiving it and all its children (default scope)"""
        self.makeSearch(baseObject='ou=stuff,dc=example,dc=com')
        self.assertSearchResults([
            {
                'objectName': 'ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('ou', ['stuff']),
                ]
            },
            {
                'objectName': 'cn=another,ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('cn', ['another']),
                ]
            },
            {
                'objectName': 'cn=thingie,ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('cn', ['thingie']),
                ]
            }
        ])

    def test_search_scope_oneLevel(self):
        """Searching for a tree object with receiving its children but without parent itself"""
        self.makeSearch(
            baseObject='ou=stuff,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_singleLevel
        )
        self.assertSearchResults([
            {
                'objectName': 'cn=thingie,ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('cn', ['thingie']),
                ]
            },
            {
                'objectName': 'cn=another,ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('cn', ['another']),
                ]
            }
        ])

    def test_search_scope_wholeSubtree(self):
        """
        Searching for a tree object with receiving it and all its children.
        This is a default behavior but here it is explicitly specified.
        """
        self.makeSearch(
            baseObject='ou=stuff,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_wholeSubtree
        )
        self.assertSearchResults([
            {
                'objectName': 'ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('ou', ['stuff']),
                ]
            },
            {
                'objectName': 'cn=another,ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('cn', ['another']),
                ]
            },
            {
                'objectName': 'cn=thingie,ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('cn', ['thingie']),
                ]
            }
        ])

    def test_search_scope_baseObject(self):
        """Searching for a tree object with receiving it without its children"""
        self.makeSearch(
            baseObject='ou=stuff,dc=example,dc=com',
            scope=pureldap.LDAP_SCOPE_baseObject
        )
        self.assertSearchResults([
            {
                'objectName': 'ou=stuff,dc=example,dc=com',
                'attributes': [
                    ('objectClass', ['a', 'b']),
                    ('ou', ['stuff']),
                ]
            }
        ])

    def test_search_all_attributes(self):
        """
        Search request with the list of attributes passed as '*'
        returns objects with all their attributes
        """
        self.makeSearch(
            baseObject='cn=thingie,ou=stuff,dc=example,dc=com',
            attributes=['*']
        )
        self.assertSearchResults([
            {
                'objectName': 'cn=thingie,ou=stuff,dc=example,dc=com',
                'attributes': [
                     ('objectClass', ['a', 'b']),
                     ('cn', ['thingie']),
                ]
            }
        ])

    def test_rootDSE(self):
        """Searching for a root object"""
        self.makeSearch(
            baseObject='',
            scope=pureldap.LDAP_SCOPE_baseObject,
            filter=pureldap.LDAPFilter_present('objectClass')
        )
        self.assertSearchResults([
            {
                'objectName': '',
                'attributes': [
                    ('supportedLDAPVersion', ['3']),
                    ('namingContexts', ['dc=example,dc=com']),
                    ('supportedExtension', [pureldap.LDAPPasswordModifyRequest.oid]),
                ]
            }
        ])

    def test_delete(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPDelRequest(self.thingie.dn.getText()),
                id=2).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPDelResponse(resultCode=0),
                id=2).toWire())
        d = self.stuff.children()
        d.addCallback(lambda actual: self.assertCountEqual(actual, [self.another]))
        return d

    def test_add_success(self):
        dn = 'cn=new,ou=stuff,dc=example,dc=com'
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPAddRequest(
                    entry=dn,
                    attributes=[
                        (
                            pureldap.LDAPAttributeDescription("objectClass"),
                            pureber.BERSet(
                                value=[
                                    pureldap.LDAPAttributeValue('something')
                                ])
                        )
                    ]),
                id=2).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPAddResponse(
                    resultCode=ldaperrors.Success.resultCode),
                id=2).toWire())
        # tree changed
        d = self.stuff.children()
        d.addCallback(lambda actual: self.assertCountEqual(
            actual,
            [
                self.thingie,
                self.another,
                inmemory.ReadOnlyInMemoryLDAPEntry(
                    b'cn=new,ou=stuff,dc=example,dc=com',
                    {b'objectClass': [b'something']})
            ]))
        return d

    def test_add_fail_existsAlready(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPAddRequest(
                    entry=self.thingie.dn.getText(),
                    attributes=[
                        (
                            pureldap.LDAPAttributeDescription("objectClass"),
                            pureber.BERSet(
                                value=[
                                    pureldap.LDAPAttributeValue('something'),
                                ])
                        )
                    ]),
                id=2).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPAddResponse(
                    resultCode=ldaperrors.LDAPEntryAlreadyExists.resultCode,
                    errorMessage=self.thingie.dn.getText()),
                id=2).toWire())
        # tree did not change
        d = self.stuff.children()
        d.addCallback(lambda actual: self.assertCountEqual(actual, [self.thingie, self.another]))
        return d

    def test_modifyDN_rdnOnly_deleteOldRDN_success(self):
        newrdn = 'cn=thingamagic'
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPModifyDNRequest(
                    entry=self.thingie.dn.getText(),
                    newrdn=newrdn,
                    deleteoldrdn=True),
                id=2).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPModifyDNResponse(
                    resultCode=ldaperrors.Success.resultCode),
                id=2).toWire())
        # tree changed
        d = self.stuff.children()
        d.addCallback(lambda actual: self.assertCountEqual(
            actual,
            [
                inmemory.ReadOnlyInMemoryLDAPEntry(
                    '%s,ou=stuff,dc=example,dc=com' % newrdn,
                    {
                        'objectClass': ['a', 'b'],
                        'cn': ['thingamagic']
                    }),
                self.another,
            ]))
        return d

    def test_modify(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPModifyRequest(
                    self.stuff.dn.getText(),
                    modification=[
                        delta.Add('foo', ['bar']).asLDAP(),
                    ]),
                id=2).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPModifyResponse(
                    resultCode=ldaperrors.Success.resultCode),
                id=2).toWire())
        # tree changed
        self.assertEqual(
            self.stuff,
            inmemory.ReadOnlyInMemoryLDAPEntry(
                'ou=stuff,dc=example,dc=com',
                {
                    b'objectClass': [b'a', b'b'],
                    b'ou': [b'stuff'],
                    b'foo': [b'bar']
                }))

    def test_extendedRequest_unknown(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedRequest(
                    requestName='42.42.42',
                    requestValue='foo'),
                id=2).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    errorMessage='Unknown extended request: 42.42.42'),
                id=2).toWire())

    def test_passwordModify_notBound(self):
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity='cn=thingie,ou=stuff,dc=example,dc=com',
                    newPasswd='hushhush'),
                id=2).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPStrongAuthRequired.resultCode,
                    responseName=pureldap.LDAPPasswordModifyRequest.oid),
                id=2).toWire())

    def test_passwordModify_simple(self):
        data = {'committed': False}

        def onCommit_(result, info):
            info['committed'] = result
            return result

        wrapCommit(self.thingie, onCommit_, data)
        # first bind to some entry
        self.thingie['userPassword'] = ['{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8=']  # "secret"
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn='cn=thingie,ou=stuff,dc=example,dc=com',
                    auth=b'secret'),
                id=4).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0,
                    matchedDN='cn=thingie,ou=stuff,dc=example,dc=com'),
                id=4).toWire())
        self.server.transport.clear()
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPPasswordModifyRequest(
                    userIdentity='cn=thingie,ou=stuff,dc=example,dc=com',
                    newPasswd='hushhush'),
                id=2).toWire())
        self.assertEqual(data['committed'], True, "Server never committed data.")
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.Success.resultCode,
                    responseName=pureldap.LDAPPasswordModifyRequest.oid),
                id=2).toWire())
        # tree changed
        secrets = self.thingie.get('userPassword', [])
        self.assertEqual(len(secrets), 1)
        for secret in secrets:
            self.assertEqual(secret[:len(b'{SSHA}')], b'{SSHA}')
            raw = base64.decodestring(secret[len(b'{SSHA}'):])
            salt = raw[20:]
            self.assertEqual(entry.sshaDigest(b'hushhush', salt), secret)

    def test_unknownRequest(self):
        # make server miss one of the handle_* attributes
        # without having to modify the LDAPServer class
        class MockServer(ldapserver.LDAPServer):
            handle_LDAPBindRequest = property()

        self.server.__class__ = MockServer
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPBindRequest(), id=2).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPExtendedResponse(
                    resultCode=ldaperrors.LDAPProtocolError.resultCode,
                    responseName='1.3.6.1.4.1.1466.20036',
                    errorMessage='Unknown request'),
                id=2).toWire())

    def test_control_unknown_critical(self):
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPBindRequest(), id=2,
            controls=[('42.42.42.42', True, None),
                      ]).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPUnavailableCriticalExtension.resultCode,
                    errorMessage='Unknown control 42.42.42.42'),
                id=2).toWire())

    def test_control_unknown_nonCritical(self):
        self.thingie['userPassword'] = ['{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8=']  # "secret"
        self.server.dataReceived(pureldap.LDAPMessage(
            pureldap.LDAPBindRequest(dn='cn=thingie,ou=stuff,dc=example,dc=com',
                                     auth=b'secret'),
            controls=[('42.42.42.42', False, None)],
            id=4).toWire())
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0,
                    matchedDN='cn=thingie,ou=stuff,dc=example,dc=com'),
                id=4).toWire())


class TestSchema(unittest.TestCase):
    def setUp(self):
        db = inmemory.ReadOnlyInMemoryLDAPEntry('', {})
        com = db.addChild('dc=com',
                          {'objectClass': ['dcObject'],
                           'dc': ['com'],
                           })
        com.addChild('dc=example',
                     {'objectClass': ['dcObject'],
                      'dc': ['example'],
                      'subschemaSubentry': ['cn=schema'],
                      })
        db.addChild('cn=schema',
                    {'objectClass': ['TODO'],
                     'cn': ['schema'],
                     'attributeTypes': [test_schema.AttributeType_KnownValues.knownValues[0][0]],
                     'objectClasses': [test_schema.OBJECTCLASSES['organization'],
                                       test_schema.OBJECTCLASSES['organizationalUnit'],
                                       ],
                     })

        class LDAPServerFactory(protocol.ServerFactory):
            protocol = ldapserver.LDAPServer

            def __init__(self, root):
                self.root = root

        components.registerAdapter(lambda x: x.root,
                                   LDAPServerFactory,
                                   interfaces.IConnectedLDAPEntry)
        serverFactory = LDAPServerFactory(db)

        self.client = ldapclient.LDAPClient()
        server = serverFactory.buildProtocol(address.IPv4Address('TCP', 'localhost', '1024'))
        util.returnConnected(server, self.client)

    def testSimple(self):
        d = fetchschema.fetch(self.client, 'dc=example,dc=com')
        (attributeTypes, objectClasses) = util.pumpingDeferredResult(d)

        self.failUnlessEqual(
            [to_bytes(x) for x in attributeTypes],
            [to_bytes(schema.AttributeTypeDescription(x)) for x in [
                test_schema.AttributeType_KnownValues.knownValues[0][0]]])

        self.failUnlessEqual(
            [to_bytes(x) for x in objectClasses],
            [to_bytes(schema.ObjectClassDescription(x)) for x in [
                test_schema.OBJECTCLASSES['organization'],
                test_schema.OBJECTCLASSES['organizationalUnit']]])

    testSimple.todo = 'Not supported yet.'
