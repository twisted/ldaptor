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

    def test_search_backend_disconnected_before_response(self):
        """
        If one backend disconnects before it can send its search-done, the
        merger must still complete the search using the surviving
        backend's response. Previously the merger sized its response queue
        to len(self.clients) and hung waiting for the dead backend (#231).
        """
        d = self.createMergedServer(
            [
                [
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                ]
            ],
            [
                [
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                ]
            ],
        )

        def test_f(server):
            # Kill the first backend before dispatching the search; the
            # other one will do all the work.
            server.clients[0].responses = []
            server.clients[0].connectionLost(error.ConnectionDone)

            server.dataReceived(
                LDAPMessage(
                    LDAPSearchRequest(baseObject="dc=example,dc=com"),
                    id=3,
                ).toWire()
            )

            self.assertEqual(
                server.transport.value(),
                LDAPMessage(
                    LDAPSearchResultEntry("cn=foo,dc=example,dc=com", [("a", ["b"])]),
                    id=3,
                ).toWire()
                + LDAPMessage(
                    LDAPSearchResultDone(ldaperrors.Success.resultCode), id=3
                ).toWire(),
            )

        d.addCallback(test_f)
        return d

    def test_search_backend_disconnects_mid_flight(self):
        """
        A backend that has already received a request but dies before it
        can send its LDAPSearchResultDone must not hang the search. The
        disconnect callback shrinks the expected-response count so the
        surviving backend's response completes the merge (#231).

        LDAPClientTestDriver replays queued responses synchronously on
        each send, so we drive the merger's ``queue`` directly to mimic
        "one Done in, then the peer dies".
        """
        d = self.createMergedServer([[]], [[]])

        def test_f(server):
            # One backend has already produced its Done -- pretend it did.
            server.queue(3, LDAPSearchResultDone(ldaperrors.Success.resultCode))
            self.assertIn(3, server.merge_map)
            self.assertEqual(server.merge_map[3]["expected"], 2)
            self.assertEqual(len(server.merge_map[3]["responses"]), 1)

            # Now the other backend dies without responding.
            server.clients[1].responses = []
            server.clients[1].connectionLost(error.ConnectionDone)

            self.assertNotIn(
                3, server.merge_map, "disconnect should have completed the merge"
            )
            self.assertEqual(
                server.transport.value(),
                LDAPMessage(
                    LDAPSearchResultDone(ldaperrors.Success.resultCode),
                    id=3,
                ).toWire(),
            )

        d.addCallback(test_f)
        return d

    def test_search_all_backends_disconnect(self):
        """
        If every backend disconnects with a merge still outstanding, the
        merger emits a synthetic ``LDAPSearchResultDone`` with
        ``LDAPOther`` rather than hanging (#231).
        """
        d = self.createMergedServer([[]], [[]])

        def test_f(server):
            # A search is in flight against both backends, no responses
            # yet arrived.
            server.merge_map[7] = {"expected": 2, "responses": []}

            for c in list(server.clients):
                c.responses = []
                c.connectionLost(error.ConnectionDone)

            self.assertNotIn(7, server.merge_map)
            self.assertEqual(
                server.transport.value(),
                LDAPMessage(
                    LDAPSearchResultDone(
                        resultCode=ldaperrors.LDAPOther.resultCode,
                        errorMessage=b"All backend LDAP connections lost",
                    ),
                    id=7,
                ).toWire(),
            )

        d.addCallback(test_f)
        return d

    def test_disconnect_paths_are_defensive(self):
        """
        Cover the remaining defensive branches in the merger's disconnect
        + dispatch paths so future regressions surface (#231):

        * ``_cbClientLost`` on a proto that was already pruned.
        * ``_checkComplete`` on an id that has already been finalized.
        * ``_clientQueue`` skipping a client whose ``connected`` flag was
          flipped without a ``notifyOnDisconnect`` firing.
        * ``_clientQueue`` swallowing ``LDAPClientConnectionLostException``.
        """
        d = self.createMergedServer([[]], [[]])

        def test_f(server):
            # 1. Re-fire disconnect for a client that's already been
            #    pruned -- proto not in self.clients branch.
            already_gone = server.clients[0]
            server._cbClientLost(None, already_gone)
            server._cbClientLost(None, already_gone)

            # 2. _checkComplete on an unknown id -- entry is None branch.
            server._checkComplete(9999)

            # 3. _clientQueue skips a client whose .connected is falsy
            #    even though it hasn't been pruned.
            stale = server.clients[0]
            stale.connected = 0
            calls = list(stale.sent)
            server._clientQueue(
                LDAPSearchRequest(baseObject="dc=example,dc=com"),
                None,
                lambda *_: None,
            )
            self.assertEqual(
                stale.sent, calls, "disconnected client should not have been sent to"
            )

            # 4. _clientQueue swallows LDAPClientConnectionLostException.
            from ldaptor.protocols.ldap.ldapclient import (
                LDAPClientConnectionLostException,
            )

            def _raise(*_a, **_kw):
                raise LDAPClientConnectionLostException()

            stale.connected = 1  # pass the guard, force the raise instead
            stale.send_multiResponse = _raise
            server._clientQueue(
                LDAPSearchRequest(baseObject="dc=example,dc=com"),
                None,
                lambda *_: None,
            )
            # No crash means the except caught it.

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
