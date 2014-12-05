"""
Test cases for ldaptor.protocols.ldap.proxybase module.
"""

from twisted.internet import error, defer
from twisted.internet.task import Clock
from twisted.trial import unittest
from ldaptor.protocols.ldap import proxybase, ldaperrors
from ldaptor.protocols import pureldap
from ldaptor import testutil

class RequestInterceptingProxy(proxybase.ProxyBase):
    """
    A test LDAP proxy that does not forward requests but instead 
    responses with pre-determined responses.
    """
    responses = [pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode)]
    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Don't forward the message to the proxied service-- instead
        reply with predetermined responses.
        """
        for response in self.responses:
            reply(response)
        return defer.succeed(None)

class ResponseInterceptingProxy(proxybase.ProxyBase):
    """
    A test LDAP proxy that intercepts and modifies search results.
    """
    new_attrib = ('frotz', 'xyzzy')
    def handleProxiedResponse(self, response, request, controls):
        """
        If the response is an LDAPSearchResultEntry, modify
        the attribute list
        """
        if isinstance(response, pureldap.LDAPSearchResultEntry):
            key, value = self.new_attrib
            response.attributes.append((key, [value]))
        return defer.succeed(response)

class ProxyBase(unittest.TestCase):
    def createServer(self, *responses, **kwds):
        """
        Create a server for each test.
        """
        protocol = kwds.get("protocol", proxybase.ProxyBase)
        clock = Clock()
        proto_args = dict(reactor_=clock)
        server = testutil.createServer(protocol, *responses, proto_args=proto_args)
        return server

    def test_bind(self):
        """
        When binding to the server an `LDAPBindResponse` with a successful 
        result code.is written to the transport.
        """
        server = self.createServer([pureldap.LDAPBindResponse(resultCode=0),])
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4)))
        server.reactor.advance(1)
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=4)))

    def test_search(self):
        """
        When performing an LDAP search against the server; the search results and 
        a single "search done" response is written to the transport.
        """
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
        """
        The server disconnects from the client gracefully when the 
        client signals its intent to unbind.
        """
        server = self.createServer([pureldap.LDAPBindResponse(resultCode=0),], [],)
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
        """
        The server disconects correctly when the client terminates the
        connection without sending an unbind request.
        """
        server = self.createServer([pureldap.LDAPBindResponse(resultCode=0),], [],)
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

    def test_intercepted_search_request(self):
        """
        When performing an LDAP search against the server; the requests are
        intercepted and custom responses are written to the transport.
        """
        server = self.createServer(
            [pureldap.LDAPBindResponse(resultCode=0),],
            [
                pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com', [('a', ['b'])]),
                pureldap.LDAPSearchResultEntry('cn=bar,dc=example,dc=com', [('b', ['c'])]),
                pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
            ],
            protocol=RequestInterceptingProxy)
        server.responses = [
            pureldap.LDAPSearchResultEntry('cn=xyzzy,dc=example,dc=com', [('frobnitz', ['zork'])]),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),]
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1)))
        server.reactor.advance(1)
        self.assertEquals(len(server.clientTestDriver.sent), 0)
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry('cn=xyzzy,dc=example,dc=com', [('frobnitz', ['zork'])]), id=1))
                          + str(pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode), id=1)))

    def test_intercepted_search_response(self):
        """
        When performing an LDAP search against the server; the search results are 
        intercepted and modified by the proxy.
        """
        server = self.createServer([pureldap.LDAPBindResponse(resultCode=0),],
                                   [pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com', [('a', ['b'])]),
                                     pureldap.LDAPSearchResultEntry('cn=bar,dc=example,dc=com', [('b', ['c'])]),
                                     pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),],
                                    protocol=ResponseInterceptingProxy)
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2)))
        server.dataReceived(str(pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=3)))
        server.reactor.advance(1)
        self.assertEquals(server.transport.value(),
                          str(pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry('cn=foo,dc=example,dc=com', [('a', ['b']), ('frotz', ['xyzzy'])]), id=3))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultEntry('cn=bar,dc=example,dc=com', [('b', ['c']), ('frotz', ['xyzzy'])]), id=3))
                          +str(pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3)))
