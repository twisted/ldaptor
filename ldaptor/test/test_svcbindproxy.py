"""
Test cases for ldaptor.protocols.ldap.svcbindproxy module.
"""

from twisted.trial import unittest
from twisted.internet import reactor
from ldaptor.protocols.ldap import svcbindproxy, ldaperrors
from ldaptor.protocols import pureldap, pureber
from ldaptor import testutil

class ServiceBindingProxy(unittest.TestCase):
    berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())))

    def createServer(self, services, fallback=None, responses=[]):
        return testutil.createServer(lambda overrides: svcbindproxy.ServiceBindingProxy(
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
            [ pureldap.LDAPSearchResultEntry('cn=jack,dc=example,dc=com',
                                             attributes=[('servicePassword', ['wrong', 'bad', 'not-matching'])]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
              ],
            ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(pureldap.LDAPSearchRequest(baseObject='cn=jack,dc=example,dc=com',
                                                     scope=0,
                                                     derefAliases=0,
                                                     sizeLimit=0,
                                                     timeLimit=0,
                                                     typesOnly=0,
                                                     filter=pureldap.LDAPFilter_present(value='objectClass'),
                                                     attributes=('servicePassword',)))
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
            [ pureldap.LDAPSearchResultEntry('cn=jack,dc=example,dc=com',
                                             attributes=[('servicePassword', ['wrong', 'bad', 'not-matching'])]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
              ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.Success.resultCode),
              ],
            ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(pureldap.LDAPSearchRequest(baseObject='cn=jack,dc=example,dc=com',
                                                     scope=0,
                                                     derefAliases=0,
                                                     sizeLimit=0,
                                                     timeLimit=0,
                                                     typesOnly=0,
                                                     filter=pureldap.LDAPFilter_present(value='objectClass'),
                                                     attributes=('servicePassword',)),
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
            [ pureldap.LDAPSearchResultEntry('cn=jack,dc=example,dc=com',
                                             attributes=[('servicePassword', ['wrong foo', 'illegal', 'not-matching quux'])]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
              ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode),
              ],
            ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(pureldap.LDAPSearchRequest(baseObject='cn=jack,dc=example,dc=com',
                                                     scope=0,
                                                     derefAliases=0,
                                                     sizeLimit=0,
                                                     timeLimit=0,
                                                     typesOnly=0,
                                                     filter=pureldap.LDAPFilter_present(value='objectClass'),
                                                     attributes=('servicePassword',)),
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
            [ pureldap.LDAPSearchResultEntry('cn=jack,dc=example,dc=com',
                                             attributes=[('servicePassword', ['wrong foo',
                                                                              'illegal',
                                                                              'svc1 {SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8=', #foo
                                                                              'svc3 {SSHA}1feEJLgP7OB5mUKU/fYJzBoAGlOrze8=', #secret
                                                                              'not-matching'])]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
              ],
            ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='secret'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(pureldap.LDAPSearchRequest(baseObject='cn=jack,dc=example,dc=com',
                                                     scope=0,
                                                     derefAliases=0,
                                                     sizeLimit=0,
                                                     timeLimit=0,
                                                     typesOnly=0,
                                                     filter=pureldap.LDAPFilter_present(value='objectClass'),
                                                     attributes=('servicePassword',)),
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
            [ pureldap.LDAPSearchResultEntry('cn=jack,dc=example,dc=com',
                                             attributes=[('servicePassword', ['wrong foo',
                                                                              'illegal',
                                                                              'svc1 {SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8=', #foo
                                                                              'svc3 {SSHA}1feEJLgP7OB5mUKU/fYJzBoAGlOrze8=', #secret
                                                                              'not-matching'])]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
              ],
            ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='foo'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(pureldap.LDAPSearchRequest(baseObject='cn=jack,dc=example,dc=com',
                                                     scope=0,
                                                     derefAliases=0,
                                                     sizeLimit=0,
                                                     timeLimit=0,
                                                     typesOnly=0,
                                                     filter=pureldap.LDAPFilter_present(value='objectClass'),
                                                     attributes=('servicePassword',)),
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
            [ pureldap.LDAPSearchResultEntry('cn=jack,dc=example,dc=com',
                                             attributes=[('servicePassword', ['wrong foo',
                                                                              'illegal',
                                                                              'svc1 {SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8=', #foo
                                                                              'svc3 {SSHA}1feEJLgP7OB5mUKU/fYJzBoAGlOrze8=', #secret
                                                                              'not-matching'])]),
              pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
              ],
            [ pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode),
              ],
            ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'), id=4)))
        reactor.iterate() #TODO
        client = server.client

        client.assertSent(pureldap.LDAPSearchRequest(baseObject='cn=jack,dc=example,dc=com',
                                                     scope=0,
                                                     derefAliases=0,
                                                     sizeLimit=0,
                                                     timeLimit=0,
                                                     typesOnly=0,
                                                     filter=pureldap.LDAPFilter_present(value='objectClass'),
                                                     attributes=('servicePassword',)),
                          pureldap.LDAPBindRequest(dn='cn=jack,dc=example,dc=com', auth='wrong-s3krit'))
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode), id=4)))
