"""
Test cases for ldaptor.protocols.ldap.svcbindproxy module.
"""

from twisted.trial import unittest
from twisted.internet import reactor
from ldaptor.protocols.ldap import svcbindproxy, ldaperrors
from ldaptor.protocols import pureldap, pureber
from ldaptor import config, ldapfilter, testutil

class ServiceBindingProxy(unittest.TestCase):
    berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())))

    def setUp(self):
        self.cfg = config.loadConfig(
            configFiles=[],
            reload=True)
        self.config = config.LDAPConfig(baseDN='dc=example,dc=com')

    def createServer(self, services, fallback=None, responses=[]):
        return testutil.createServer(lambda overrides: svcbindproxy.ServiceBindingProxy(
            config=self.config,
            services=services,
            fallback=fallback,
            overrides=overrides,
            ),
                                     *responses)
    
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
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc1))'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc2))'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc3))'),
                                       attributes=('1.1',)),
            )
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode), id=4)))

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
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc1))'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc2))'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc3))'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='s3krit'))
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode), id=4)))

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
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc1))'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc2))'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc3))'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'))
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode), id=4)))


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
            
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='secret'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc1))'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn=r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='secret'),
            )
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode,
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
            
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='secret'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc1))'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn=r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='secret'),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc2))'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc3))'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn='cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='secret'),
            )
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode,
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
            
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc1))'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn=r'cn=svc1+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='wrong-s3krit'),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc2))'),
                                       attributes=('1.1',)),
            pureldap.LDAPSearchRequest(baseObject='dc=example,dc=com',
                                       derefAliases=0,
                                       sizeLimit=0,
                                       timeLimit=0,
                                       typesOnly=0,
                                       filter=ldapfilter.parseFilter('(&(objectClass=serviceSecurityObject)(owner=cn=jack,dc=example,dc=com)(cn=svc3))'),
                                       attributes=('1.1',)),
            pureldap.LDAPBindRequest(dn='cn=svc3+owner=cn\=jack\,dc\=example\,dc\=com,dc=example,dc=com', auth='wrong-s3krit'),
            pureldap.LDAPBindRequest(version=3, dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'),
            )
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode), id=4)))
