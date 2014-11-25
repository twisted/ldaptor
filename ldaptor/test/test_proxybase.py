"""
Test cases for ldaptor.protocols.ldap.proxybase module.
"""

from twisted.internet import error
from twisted.internet.task import Clock
from twisted.trial import unittest
from ldaptor.protocols.ldap import proxybase, ldaperrors
from ldaptor.protocols import pureldap
from ldaptor import testutil

class ProxyBase(unittest.TestCase):
    def createServer(self, *responses):
        clock = Clock()
        proto_args = dict(reactor_=clock)
        server = testutil.createServer(proxybase.ProxyBase, *responses, proto_args=proto_args)
        return server

    def test_bind(self):
        server = self.createServer([ pureldap.LDAPBindResponse(resultCode=0),
                                     ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4)))
        server.reactor.advance(1)
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=4)))

    def test_search(self):
        server = self.createServer([ pureldap.LDAPBindResponse(resultCode=0),
                                     ],
                                   [ pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com', [('a', ['b'])]),
                                     pureldap.LDAPSearchResultEntry('cn=bar,dc=example,dc=com', [('b', ['c'])]),
                                     pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
                                     ],
                                   )
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2)))
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=3)))
        server.reactor.advance(1)
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com', [('a', ['b'])]), id=3))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry('cn=bar,dc=example,dc=com', [('b', ['c'])]), id=3))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3)))

    def test_unbind_clientUnbinds(self):
        server = self.createServer([ pureldap.LDAPBindResponse(resultCode=0),
                                     ],
                                   [],
                                   )
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2)))
        server.reactor.advance(1)
        client = server.client
        client.assertSent(pureldap.LDAPBindRequest())
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2)))
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=3)))
        server.connectionLost(error.ConnectionDone)
        server.reactor.advance(1)
        client.assertSent(pureldap.LDAPBindRequest(),
                          pureldap.LDAPUnbindRequest())
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2)))

    def test_unbind_clientEOF(self):
        server = self.createServer([ pureldap.LDAPBindResponse(resultCode=0),
                                     ],
                                   [],
                                   )
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2)))
        server.reactor.advance(1)
        client = server.client
        client.assertSent(pureldap.LDAPBindRequest())
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2)))
        server.connectionLost(error.ConnectionDone)
        server.reactor.advance(1)
        client.assertSent(pureldap.LDAPBindRequest(),
                          'fake-unbind-by-LDAPClientTestDriver')
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2)))
