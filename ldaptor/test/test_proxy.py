"""
Test cases for ldaptor.protocols.ldap.proxy module.
"""

from twisted.trial import unittest
from twisted.internet import reactor, error
from ldaptor.protocols.ldap import proxy, ldaperrors
from ldaptor.protocols import pureldap
from ldaptor import testutil

class Proxy(unittest.TestCase):
    def createServer(self, *responses):
        return testutil.createServer(proxy.Proxy, *responses)

    def test_bind(self):
        server = self.createServer([ pureldap.LDAPBindResponse(resultCode=0),
                                     ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4)))
        reactor.iterate() #TODO
        self.assertEqual(server.transport.value(),
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
        reactor.iterate() #TODO
        self.assertEqual(server.transport.value(),
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
        reactor.iterate() #TODO
        client = server.client
        client.assertSent(pureldap.LDAPBindRequest())
        self.assertEqual(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2)))
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=3)))
        server.connectionLost(error.ConnectionDone)
        reactor.iterate() #TODO
        client.assertSent(pureldap.LDAPBindRequest(),
                          pureldap.LDAPUnbindRequest())
        self.assertEqual(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2)))

    def test_unbind_clientEOF(self):
        server = self.createServer([ pureldap.LDAPBindResponse(resultCode=0),
                                     ],
                                   [],
                                   )
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2)))
        reactor.iterate() #TODO
        client = server.client
        client.assertSent(pureldap.LDAPBindRequest())
        self.assertEqual(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2)))
        server.connectionLost(error.ConnectionDone)
        reactor.iterate() #TODO
        client.assertSent(pureldap.LDAPBindRequest(),
                          'fake-unbind-by-LDAPClientTestDriver')
        self.assertEqual(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2)))
