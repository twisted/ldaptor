"""
Test cases for ldaptor.protocols.ldap.proxy module.
"""

from twisted.trial import unittest
from twisted.trial.util import deferredResult
from twisted.internet import protocol, address, reactor
from twisted.python import components
from ldaptor import inmemory, interfaces, schema
from ldaptor.protocols.ldap import proxy, ldaperrors
from ldaptor.protocols import pureldap, pureber
from twisted.test import proto_helpers
from ldaptor.test import util, test_schema
from ldaptor.testutil import LDAPClientTestDriver

class Proxy(unittest.TestCase):
    def createServer(self, *responses):
        def createClient(factory):
            factory.doStart()
            #TODO factory.startedConnecting(c)
            proto = factory.buildProtocol(addr=None)
        overrides = {
            '': createClient,
            }
        server = proxy.Proxy(overrides)
        server.protocol = lambda : LDAPClientTestDriver(*responses)
        server.transport = proto_helpers.StringTransport()
        server.connectionMade()
        return server

    def test_bind(self):
        server = self.createServer([ pureldap.LDAPBindResponse(resultCode=0),
                                     ])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4)))
        reactor.iterate() #TODO
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
        reactor.iterate() #TODO
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com', [('a', ['b'])]), id=3))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry('cn=bar,dc=example,dc=com', [('b', ['c'])]), id=3))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3)))
