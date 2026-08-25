"""
Test cases for ldaptor.protocols.ldap.proxybase module.
"""

from functools import partial
import itertools

from twisted.internet import error, defer
from twisted.internet.task import Clock
from twisted.trial import unittest
from twisted.test import proto_helpers

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

    delays = itertools.cycle([1, 5])
    new_attrib = ("frotz", "xyzzy")

    def handleProxiedResponse(self, response, request, controls):
        """
        If the response is an LDAPSearchResultEntry, modify
        the attribute list
        """
        if isinstance(response, pureldap.LDAPSearchResultEntry):
            key, value = self.new_attrib
            response.attributes.append((key, [value]))
        d = defer.Deferred()
        d.addCallback(self._afterDelay)
        self.reactor.callLater(next(self.delays), d.callback, response)
        return d

    def _afterDelay(self, response):
        return response


class WontConnectError(Exception):
    pass


def failToConnectToServer(reactor, delay=0):
    d = defer.Deferred()

    def onConnect():
        d.errback(fail=WontConnectError("Test LDAP client refuses to connect."))

    reactor.callLater(delay, onConnect)
    return d


class ProxyBase(unittest.TestCase):
    def createServer(self, *responses, **kwds):
        """
        Create a server for each test.
        """
        protocol = kwds.get("protocol", proxybase.ProxyBase)
        clock = Clock()
        clock = kwds.get("clock", clock)
        server = protocol()
        clientTestDriver = testutil.LDAPClientTestDriver(*responses)

        def simulateConnectToServer():
            d = defer.Deferred()

            def onConnect():
                clientTestDriver.connectionMade()
                d.callback(clientTestDriver)

            clock.callLater(0, onConnect)
            return d

        clientConnector = kwds.get("clientConnector", simulateConnectToServer)
        server.clientConnector = clientConnector
        server.clientTestDriver = clientTestDriver
        server.transport = proto_helpers.StringTransport()
        server.reactor = clock
        server.connectionMade()
        return server

    def test_bind(self):
        """
        When binding to the server an `LDAPBindResponse` with a successful
        result code.is written to the transport.
        """
        server = self.createServer([pureldap.LDAPBindResponse(resultCode=0)])
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4).toWire()
        )
        server.reactor.advance(1)
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=4
            ).toWire(),
        )

    def test_search(self):
        """
        When performing an LDAP search against the server; the search results and
        a single "search done" response is written to the transport.
        """
        server = self.createServer(
            [pureldap.LDAPBindResponse(resultCode=0)],
            [
                pureldap.LDAPSearchResultEntry(
                    "cn=foo,dc=example,dc=com", [("a", ["b"])]
                ),
                pureldap.LDAPSearchResultEntry(
                    "cn=bar,dc=example,dc=com", [("b", ["c"])]
                ),
                pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
            ],
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=3).toWire()
        )
        server.reactor.advance(1)
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2).toWire()
            + pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(
                    "cn=foo,dc=example,dc=com", [("a", ["b"])]
                ),
                id=3,
            ).toWire()
            + pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(
                    "cn=bar,dc=example,dc=com", [("b", ["c"])]
                ),
                id=3,
            ).toWire()
            + pureldap.LDAPMessage(
                pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3
            ).toWire(),
        )

    def test_unbind_clientUnbinds(self):
        """
        The server disconnects from the client gracefully when the
        client signals its intent to unbind.
        """
        server = self.createServer(
            [pureldap.LDAPBindResponse(resultCode=0)],
            [],
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        server.reactor.advance(1)
        client = server.client
        client.assertSent(pureldap.LDAPBindRequest())
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=2
            ).toWire(),
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPUnbindRequest(), id=3).toWire()
        )
        server.connectionLost(error.ConnectionDone)
        server.reactor.advance(1)
        client.assertSent(pureldap.LDAPBindRequest(), pureldap.LDAPUnbindRequest())
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=2
            ).toWire(),
        )

    def test_unbind_clientEOF(self):
        """
        The server disconects correctly when the client terminates the
        connection without sending an unbind request.
        """
        server = self.createServer([pureldap.LDAPBindResponse(resultCode=0)])
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        server.reactor.advance(1)
        client = server.client
        client.assertSent(pureldap.LDAPBindRequest())
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=2
            ).toWire(),
        )
        server.connectionLost(error.ConnectionDone)
        server.reactor.advance(1)
        client.assertSent(
            pureldap.LDAPBindRequest(), "fake-unbind-by-LDAPClientTestDriver"
        )
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=2
            ).toWire(),
        )

    def test_intercepted_search_request(self):
        """
        When performing an LDAP search against the server; the requests are
        intercepted and custom responses are written to the transport.
        """
        server = self.createServer(
            [pureldap.LDAPBindResponse(resultCode=0)],
            [
                pureldap.LDAPSearchResultEntry(
                    "cn=foo,dc=example,dc=com", [("a", ["b"])]
                ),
                pureldap.LDAPSearchResultEntry(
                    "cn=bar,dc=example,dc=com", [("b", ["c"])]
                ),
                pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
            ],
            protocol=RequestInterceptingProxy,
        )
        server.responses = [
            pureldap.LDAPSearchResultEntry(
                "cn=xyzzy,dc=example,dc=com", [("frobnitz", ["zork"])]
            ),
            pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
        ]
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=1).toWire()
        )
        server.reactor.advance(1)
        self.assertEqual(len(server.clientTestDriver.sent), 0)
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(
                    "cn=xyzzy,dc=example,dc=com", [("frobnitz", ["zork"])]
                ),
                id=1,
            ).toWire()
            + pureldap.LDAPMessage(
                pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode), id=1
            ).toWire(),
        )

    def test_intercepted_search_response(self):
        """
        When performing an LDAP search against the server; the search results are
        intercepted and modified by the proxy.
        """
        server = self.createServer(
            [pureldap.LDAPBindResponse(resultCode=0)],
            [
                pureldap.LDAPSearchResultEntry(
                    "cn=foo,dc=example,dc=com", [("a", ["b"])]
                ),
                pureldap.LDAPSearchResultEntry(
                    "cn=bar,dc=example,dc=com", [("b", ["c"])]
                ),
                pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode),
            ],
            protocol=ResponseInterceptingProxy,
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPSearchRequest(), id=3).toWire()
        )
        server.reactor.advance(1)
        server.reactor.advance(5)
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(pureldap.LDAPBindResponse(resultCode=0), id=2).toWire()
            + pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(
                    "cn=foo,dc=example,dc=com", [("a", ["b"]), ("frotz", ["xyzzy"])]
                ),
                id=3,
            ).toWire()
            + pureldap.LDAPMessage(
                pureldap.LDAPSearchResultEntry(
                    "cn=bar,dc=example,dc=com", [("b", ["c"]), ("frotz", ["xyzzy"])]
                ),
                id=3,
            ).toWire()
            + pureldap.LDAPMessage(
                pureldap.LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3
            ).toWire(),
        )

    def test_cannot_connect_to_proxied_server_no_pending_requests(self):
        """
        When making a request and the proxy cannot connect to the proxied server, the
        connection is terminated.
        """
        clock = Clock()
        connector = partial(failToConnectToServer, clock)
        server = self.createServer([], clientConnector=connector, clock=clock)
        self.assertEqual(connector, server.clientConnector)
        server.reactor.advance(1)
        self.assertEqual(server.transport.value(), b"")

    def test_cannot_connect_to_proxied_server_pending_requests(self):
        """
        When making a request and the proxy cannot connect to the proxied server,
        pending BIND and startTLS requests are replied to and the connection
        is closed.
        """
        clock = Clock()
        connector = partial(failToConnectToServer, clock)
        server = self.createServer([], clientConnector=connector, clock=clock)
        self.assertEqual(connector, server.clientConnector)
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4).toWire()
        )
        server.reactor.advance(2)
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=52), id=4
            ).toWire(),
        )

    def test_health_check_closes_connection_to_proxied_server(self):
        """
        When the client disconnects immediately and before the connection to the proxied server has
        been established, the proxy terminates the connection to the proxied server.
        Messages sent by the client are discarded.
        """
        request = pureldap.LDAPBindRequest()
        message = pureldap.LDAPMessage(request, id=4)
        server = self.createServer()
        # Send a message, message is queued
        server.dataReceived(message.toWire())
        self.assertEqual(len(server.queuedRequests), 1)
        self.assertEqual(server.queuedRequests[0][0], request)
        # Lose connection, message is discarded
        server.connectionLost(error.ConnectionDone)
        server.reactor.advance(1)
        self.assertIsNone(server.client)
        self.assertFalse(server.clientTestDriver.connected)
        self.assertEqual(server.queuedRequests, [])
