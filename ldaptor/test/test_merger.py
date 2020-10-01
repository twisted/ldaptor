from twisted.internet import error
from ldaptor import config, testutil
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.pureldap import (
    LDAPBindResponse,
    LDAPBindRequest,
    LDAPUnbindRequest,
    LDAPSearchResultEntry,
    LDAPMessage,
    LDAPSearchRequest,
    LDAPSearchResultDone,
    LDAPAddRequest,
    LDAPAddResponse,
    LDAPDelRequest,
    LDAPDelResponse,
    LDAPModifyRequest,
    LDAPModifyResponse,
    LDAPModifyDNRequest,
    LDAPModifyDNResponse,
    LDAPExtendedRequest,
    LDAPExtendedResponse,
)
from twisted.test import proto_helpers
from twisted.trial import unittest

from ldaptor.protocols.ldap.merger import MergedLDAPServer


class MergedLDAPServerTest(unittest.TestCase):
    def createMergedServer(self, *responses):
        """
        Create an MergedLDAP server for testing. Initialize with
        len(responses) clients.
        :param responses: The responses to initialize the `LDAPClientTestDrives`.
        :type responses: args of lists of lists
        :return a deferred, fires when server finished connecting
        """

        def createClient(factory):
            factory.doStart()
            proto = factory.buildProtocol(addr=None)
            proto.connectionMade()

        clients = []
        for r in responses:
            clients.append(testutil.LDAPClientTestDriver(*r))

        conf = config.LDAPConfig(serviceLocationOverrides={"": createClient})
        server = MergedLDAPServer([conf for _ in clients], [False for _ in clients])
        self.clients = clients * 1
        server.protocol = lambda: clients.pop()
        server.transport = proto_helpers.StringTransport()
        server.connectionMade()

        d = server._whenConnected(lambda: server)
        return d

    def test_bind_both_success(self):
        d = self.createMergedServer(
            [[LDAPBindResponse(resultCode=0)]], [[LDAPBindResponse(resultCode=0)]]
        )

        def test_f(server):
            server.dataReceived(LDAPMessage(LDAPBindRequest(), id=4).toWire())

            self.assertEqual(
                server.transport.value(),
                LDAPMessage(LDAPBindResponse(resultCode=0), id=4).toWire(),
            )

        d.addCallback(test_f)

        return d

    def test_bind_one_invalid(self):
        d = self.createMergedServer(
            [
                [
                    LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
                ]
            ],
            [[LDAPBindResponse(resultCode=0)]],
        )

        def test_f(server):
            server.dataReceived(LDAPMessage(LDAPBindRequest(), id=4).toWire())
            self.assertEqual(
                server.transport.value(),
                LDAPMessage(LDAPBindResponse(resultCode=0), id=4).toWire(),
            )

        d.addCallback(test_f)
        return d

    def test_bind_both_invalid(self):
        d = self.createMergedServer(
            [
                [
                    LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
                ]
            ],
            [
                [
                    LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    )
                ]
            ],
        )

        def test_f(server):
            server.dataReceived(LDAPMessage(LDAPBindRequest(), id=4).toWire())
            self.assertEqual(
                server.transport.value(),
                LDAPMessage(
                    LDAPBindResponse(
                        resultCode=ldaperrors.LDAPInvalidCredentials.resultCode
                    ),
                    id=4,
                ).toWire(),
            )

        d.addCallback(test_f)
        return d

    def test_search_merged(self):
        d = self.createMergedServer(
            [
                [
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                ]
            ],
            [
                [
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    LDAPSearchResultEntry("cn=bar2,dc=example,dc=com", [("b", ["c"])]),
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                ]
            ],
        )

        def test_f(server):
            server.dataReceived(LDAPMessage(LDAPSearchRequest(), id=3).toWire())
            self.assertEqual(
                server.transport.value(),
                LDAPMessage(
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultEntry("cn=bar2,dc=example,dc=com", [("b", ["c"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3
                ).toWire(),
            )

        d.addCallback(test_f)

        return d

    def test_search_one_invalid(self):
        d = self.createMergedServer(
            [
                [
                    LDAPSearchResultDone(
                        ldaperrors.LDAPInappropriateAuthentication.resultCode
                    )
                ]
            ],
            [
                [
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                ]
            ],
        )

        def test_f(server):
            server.dataReceived(LDAPMessage(LDAPSearchRequest(), id=3).toWire())
            self.assertEqual(
                server.transport.value(),
                LDAPMessage(
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultEntry("cn=bar,dc=example,dc=com", [("b", ["c"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3
                ).toWire(),
            )

        d.addCallback(test_f)

        return d

    def test_unbind_clientUnbinds(self):
        d = self.createMergedServer([[]], [[]])

        def test_f(server):
            server.dataReceived(LDAPMessage(LDAPUnbindRequest(), id=3).toWire())
            server.connectionLost(error.ConnectionDone)
            for c in self.clients:
                c.assertSent(LDAPUnbindRequest())
            self.assertEqual(server.transport.value(), b"")

        d.addCallback(test_f)

        return d

    def test_unbind_clientEOF(self):
        """
        No connection is done when client has nothing to say.
        """
        d = self.createMergedServer([[]], [[]])

        def test_f(server):
            server.connectionLost(error.ConnectionDone)

            self.assertEqual([], server.clients, "A connection should not be done.")
            self.assertEqual(server.transport.value(), b"")

        d.addCallback(test_f)

        return d

    def test_unwilling_to_perform(self):
        d = self.createMergedServer([[]], [[]])

        def test_f(server):
            server.dataReceived(
                LDAPMessage(LDAPAddRequest(entry="", attributes=[]), id=3).toWire()
            )
            server.dataReceived(LDAPMessage(LDAPDelRequest(entry=""), id=4).toWire())
            server.dataReceived(
                LDAPMessage(
                    LDAPModifyRequest(object="", modification=[]), id=5
                ).toWire()
            )
            server.dataReceived(
                LDAPMessage(
                    LDAPModifyDNRequest(entry="", newrdn="", deleteoldrdn=0), id=6
                ).toWire()
            )
            server.dataReceived(
                LDAPMessage(LDAPExtendedRequest(requestName=""), id=7).toWire()
            )
            for c in server.clients:
                c.assertNothingSent()

            self.assertEqual(
                server.transport.value(),
                LDAPMessage(
                    LDAPAddResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPDelResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=4,
                ).toWire()
                + LDAPMessage(
                    LDAPModifyResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=5,
                ).toWire()
                + LDAPMessage(
                    LDAPModifyDNResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=6,
                ).toWire()
                + LDAPMessage(
                    LDAPExtendedResponse(
                        resultCode=ldaperrors.LDAPUnwillingToPerform.resultCode
                    ),
                    id=7,
                ).toWire(),
            )

        d.addCallback(test_f)

        return d
