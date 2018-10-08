"""
Test cases for ldaptor.protocols.ldap.svcbindproxy module.
"""

from twisted.trial import unittest
from twisted.internet import reactor
from ldaptor.protocols.ldap import svcbindproxy, ldaperrors
from ldaptor.protocols import pureldap, pureber
from ldaptor import ldapfilter, testutil

class ServiceBindingProxy(unittest.TestCase):
    berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())))

    def createServer(self, services, fallback=None, responses=[]):
        server = testutil.createServer(lambda config: svcbindproxy.ServiceBindingProxy(
            config=config,
            services=services,
            fallback=fallback,
            ),
                                     baseDN='dc=example,dc=com',
                                     *responses)
        server.now = '20050213140302Z'
        server.timestamp = lambda : server.now
        return server

    def test_bind_noMatchingServicesFound_noFallback(self):
        server = self.createServer(
            services=['svc1',
                      'svc2',
                      'svc3',
                      ],
            fallback=False,
            responses=[
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            ])
        server.dataReceived(bytes(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc1)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc2)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc3)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            )
        self.assertEqual(server.transport.value(),
                          bytes(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode), id=4)))

    def test_bind_noMatchingServicesFound_fallback_success(self):
        server = self.createServer(
            services=['svc1',
                      'svc2',
                      'svc3',
                      ],
            fallback=True,
            responses=[
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode) ],
            ])
        server.dataReceived(bytes(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc1)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc2)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc3)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='s3krit'))
        self.assertEqual(server.transport.value(),
                          bytes(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode), id=4)))

    def test_bind_noMatchingServicesFound_fallback_badAuth(self):
        server = self.createServer(
            services=['svc1',
                      'svc2',
                      'svc3',
                      ],
            fallback=True,
            responses=[
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode),
              ],
            ])
        server.dataReceived(bytes(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc1)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc2)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc3)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'))
        self.assertEqual(server.transport.value(),
                          bytes(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode), id=4)))


    def test_bind_match_success(self):
        server = self.createServer(
            services=['svc1',
                      'svc2',
                      'svc3',
                      ],
            fallback=True,
            responses=[

            # svc1
            [ pureldap.LDAPSearchResultEntry(r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com',
                                             attributes=[]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode) ],
            ])

        server.dataReceived(bytes(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='secret'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc1)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn=r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='secret'),
            )
        self.assertEqual(server.transport.value(),
                          bytes(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode,
                                                                             matchedDN='cn=jack,dc=example,dc=com'), id=4)))

    def test_bind_match_success_later(self):
        server = self.createServer(
            services=['svc1',
                      'svc2',
                      'svc3',
                      ],
            fallback=True,
            responses=[

            # svc1
            [ pureldap.LDAPSearchResultEntry(r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com',
                                             attributes=[]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode) ],

            # svc2
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],

            # svc3
            [ pureldap.LDAPSearchResultEntry(r'cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com',
                                             attributes=[]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode) ],
            ])

        server.dataReceived(bytes(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='secret'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc1)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn=r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='secret'),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc2)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc3)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn='cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='secret'),
            )
        self.assertEqual(server.transport.value(),
                          bytes(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode,
                                                                             matchedDN='cn=jack,dc=example,dc=com'), id=4)))

    def test_bind_match_badAuth(self):
        server = self.createServer(
            services=['svc1',
                      'svc2',
                      'svc3',
                      ],
            fallback=True,
            responses=[

            # svc1
            [ pureldap.LDAPSearchResultEntry(r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com',
                                             attributes=[]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode) ],

            # svc2
            [ pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],

            # svc3
            [ pureldap.LDAPSearchResultEntry(r'cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com',
                                             attributes=[]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode) ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode) ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode) ],
            ])

        server.dataReceived(bytes(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc1)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn=r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='wrong-s3krit'),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc2)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&'
                                                                     +'(objectClass=serviceSecurityObject)'
                                                                     +'(owner=cn=jack,dc=example,dc=com)'
                                                                     +'(cn=svc3)'
                                                                     +('(|(!(validFrom=*))(validFrom<=%s))' % server.now)
                                                                     +('(|(!(validUntil=*))(validUntil>=%s))' % server.now)
                                                                     +')'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn='cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='wrong-s3krit'),
            pureldap.LDAPBindRequest(version=3, dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'),
            )
        self.assertEqual(server.transport.value(),
                          bytes(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode), id=4)))
