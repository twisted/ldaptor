"""
Test cases for ldaptor.protocols.ldap.ldapsyntax module.
"""
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer
from twisted.internet.task import Clock
from ldaptor.protocols.ldap import ldapclient, ldaperrors
from ldaptor.protocols import (
    pureber,
    pureldap,
)
from ldaptor import testutil
from ldaptor._encoder import WireStrAlias, to_bytes


class SillyMessage(WireStrAlias):
    needs_answer = True

    def __init__(self, value):
        self.value = value

    def toWire(self):
        return to_bytes(self.value)


class SillyError(Exception):
    def __str__(self):
        "Exception for test purposes."


class ConnectionLost(unittest.TestCase):
    def test_simple(self):
        c = ldapclient.LDAPClient()
        c.makeConnection(proto_helpers.StringTransport())
        d1 = c.send(SillyMessage("foo"))
        d2 = c.send(SillyMessage("bar"))
        c.connectionLost(SillyError())

        def eb(fail):
            fail.trap(SillyError)

        d1.addCallbacks(testutil.mustRaise, eb)
        d2.addCallbacks(testutil.mustRaise, eb)
        return defer.DeferredList([d1, d2], fireOnOneErrback=True)


class SendTests(unittest.TestCase):
    def create_test_client(self):
        """
        Create test client and transport.
        """
        client = ldapclient.LDAPClient()
        transport = proto_helpers.StringTransport()
        client.makeConnection(transport)
        return client, transport

    def create_test_search_req(self):
        """
        Create a test LDAP search request.
        """
        basedn = "ou=people,dc=example,dc=org"
        scope = pureldap.LDAP_SCOPE_wholeSubtree
        op = pureldap.LDAPSearchRequest(basedn, scope)
        return op

    def create_paged_search_controls(self, page_size=10, cookie=b""):
        control_value = pureber.BERSequence(
            [
                pureber.BERInteger(page_size),
                pureber.BEROctetString(cookie),
            ]
        )
        controls = [(b"1.2.840.113556.1.4.319", None, control_value.toWire())]
        return controls

    def test_bind_not_connected(self):
        client = ldapclient.LDAPClient()
        self.assertRaises(
            ldapclient.LDAPClientConnectionLostException,
            client.bind,
            "cn=foo,ou=baz,dc=example,dc=net",
        )

    def test_bind_failure(self):
        clock = Clock()
        ldapclient.reactor = clock
        client, transport = self.create_test_client()
        d = client.bind()
        clock.advance(1)
        error = ldaperrors.LDAPInvalidCredentials()
        op = pureldap.LDAPBindResponse(error.resultCode)
        response = pureldap.LDAPMessage(op)
        response.id -= 1
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)

        def cb_(thing):
            expected = ldaperrors.LDAPInvalidCredentials
            self.assertEqual(expected, type(thing.value))

        d.addErrback(cb_)
        return d

    def test_bind_success(self):
        clock = Clock()
        ldapclient.reactor = clock
        client, transport = self.create_test_client()
        creds = (b"cn=foo,ou=baz,dc=example,dc=net", b"secret")
        d = client.bind(*creds)
        clock.advance(1)
        op = pureldap.LDAPBindResponse(resultCode=0, matchedDN=creds[0])
        response = pureldap.LDAPMessage(op)
        response.id -= 1
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)

        def cb_(thing):
            self.assertEqual((creds[0], None), thing)

        d.addCallback(cb_)
        return d

    def test_unbind(self):
        client, transport = self.create_test_client()
        client.unbind()

    def test_unbind_not_connected(self):
        client = ldapclient.LDAPClient()
        self.assertRaises(Exception, client.unbind)

    def test_TLS_failure(self):
        clock = Clock()
        ldapclient.reactor = clock
        client, transport = self.create_test_client()
        d = client.startTLS()
        clock.advance(1)
        error = ldaperrors.LDAPOperationsError()
        op = pureldap.LDAPStartTLSResponse(error.resultCode)
        response = pureldap.LDAPMessage(op)
        response.id -= 1
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)

        def cb_(thing):
            expected = ldaperrors.LDAPOperationsError
            self.assertEqual(expected, type(thing.value))

        d.addErrback(cb_)
        return d

    def test_unsolicited(self):
        client, transport = self.create_test_client()
        response = pureldap.LDAPMessage(pureldap.LDAPSearchResultDone(0), id=0)
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)

    def test_send_not_connected(self):
        client = ldapclient.LDAPClient()
        op = self.create_test_search_req()
        self.assertRaises(
            ldapclient.LDAPClientConnectionLostException,
            client.send_multiResponse,
            op,
            None,
        )

    def test_send_multiResponse(self):
        client, transport = self.create_test_client()
        op = self.create_test_search_req()
        d = client.send_multiResponse(op, None)
        expected_value = pureldap.LDAPMessage(op)
        expected_value.id -= 1
        expected_bytestring = expected_value.toWire()
        self.assertEqual(transport.value(), expected_bytestring)
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0), id=expected_value.id
        )
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)
        self.assertEqual(response.value, self.successResultOf(d))

    def test_send_multiResponse_with_handler(self):
        client, transport = self.create_test_client()
        client.debug = True
        op = self.create_test_search_req()
        results = []

        def collect_result_(result):
            results.append(result)
            if isinstance(result, pureldap.LDAPSearchResultDone):
                return True
            return False

        client.send_multiResponse(op, collect_result_)
        expected_value = pureldap.LDAPMessage(op)
        expected_value.id -= 1
        expected_bytestring = expected_value.toWire()
        self.assertEqual(transport.value(), expected_bytestring)
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultEntry("cn=foo,ou=baz,dc=example,dc=net", {}),
            id=expected_value.id,
        )
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0), id=expected_value.id
        )
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)
        self.assertEqual(response.value, results[1])

    def test_send_multiResponse_ex(self):
        client, transport = self.create_test_client()
        op = self.create_test_search_req()
        controls = self.create_paged_search_controls()
        d = client.send_multiResponse_ex(op, controls)
        expected_value = pureldap.LDAPMessage(op, controls)
        expected_value.id -= 1
        expected_bytestring = expected_value.toWire()
        self.assertEqual(transport.value(), expected_bytestring)
        resp_controls = self.create_paged_search_controls(0, "magic")
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0),
            id=expected_value.id,
            controls=resp_controls,
        )
        resp_bytestring = response.toWire()
        client.dataReceived(resp_bytestring)
        self.assertEqual((response.value, response.controls), self.successResultOf(d))

    def test_send_noResponse(self):
        client, transport = self.create_test_client()
        op = pureldap.LDAPAbandonRequest(id=1)
        client.send_noResponse(op)


class RepresentationTests(unittest.TestCase):
    """
    Tests that center on correct representations of objects.
    """

    def test_clientConnectionLost_rep(self):
        error = ldapclient.LDAPClientConnectionLostException()
        self.assertEqual(b"Connection lost", error.toWire())

    def test_startTLSBusyError_rep(self):
        error = ldapclient.LDAPStartTLSBusyError("xyzzy")
        expected_value = b"Cannot STARTTLS while operations on wire: 'xyzzy'"
        self.assertEqual(expected_value, error.toWire())

    def test_StartTLSInvalidResponseName_rep(self):
        error = ldapclient.LDAPStartTLSInvalidResponseName("xyzzy")
        expected_value = b"Invalid responseName in STARTTLS response: 'xyzzy'"
        self.assertEqual(expected_value, error.toWire())
