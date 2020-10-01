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
        server = self.createServer(
            [
                pureldap.LDAPBindResponse(resultCode=0),
            ]
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=4).toWire()
        )
        reactor.iterate()  # TODO
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=4
            ).toWire(),
        )

    def test_bind_sasl_no_credentials(self):
        # result code 14 is saslInprogress, with some server credentials.
        server = self.createServer(
            [
                pureldap.LDAPBindResponse(resultCode=14, serverSaslCreds="test123"),
            ]
        )

        server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(auth=("GSS-SPNEGO", None), sasl=True), id=4
            ).toWire()
        )
        reactor.iterate()  # TODO
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=14, serverSaslCreds="test123"),
                id=4,
            ).toWire(),
        )

    def test_search(self):
        server = self.createServer(
            [
                pureldap.LDAPBindResponse(resultCode=0),
            ],
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
        reactor.iterate()  # TODO
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
        server = self.createServer(
            [
                pureldap.LDAPBindResponse(resultCode=0),
            ],
            [],
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        reactor.iterate()  # TODO
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
        reactor.iterate()  # TODO
        client.assertSent(pureldap.LDAPBindRequest(), pureldap.LDAPUnbindRequest())
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=2
            ).toWire(),
        )

    def test_unbind_clientEOF(self):
        server = self.createServer(
            [
                pureldap.LDAPBindResponse(resultCode=0),
            ],
            [],
        )
        server.dataReceived(
            pureldap.LDAPMessage(pureldap.LDAPBindRequest(), id=2).toWire()
        )
        reactor.iterate()  # TODO
        client = server.client
        client.assertSent(pureldap.LDAPBindRequest())
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=2
            ).toWire(),
        )
        server.connectionLost(error.ConnectionDone)
        reactor.iterate()  # TODO
        client.assertSent(
            pureldap.LDAPBindRequest(), "fake-unbind-by-LDAPClientTestDriver"
        )
        self.assertEqual(
            server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(resultCode=0), id=2
            ).toWire(),
        )
