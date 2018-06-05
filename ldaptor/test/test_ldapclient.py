"""
Test cases for ldaptor.protocols.ldap.ldapsyntax module.
"""

from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer
from ldaptor.protocols.ldap import ldapclient
from ldaptor.protocols import (
    pureber,
    pureldap,
)
from ldaptor import testutil


class SillyMessage(object):
    needs_answer = True

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class SillyError(Exception):

    def __str__(self):
        'Exception for test purposes.'


class ConnectionLost(unittest.TestCase):

    def test_simple(self):
        c = ldapclient.LDAPClient()
        c.makeConnection(proto_helpers.StringTransport())
        d1 = c.send(SillyMessage('foo'))
        d2 = c.send(SillyMessage('bar'))
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
        basedn = "ou=people,dc=example,dc=org"
        scope = pureldap.LDAP_SCOPE_wholeSubtree
        op = pureldap.LDAPSearchRequest(
            basedn,
            scope)
        return op

    def create_paged_search_controls(self, page_size=10, cookie=b''):
        control_value = pureber.BERSequence([
            pureber.BERInteger(page_size),
            pureber.BEROctetString(cookie),
        ])
        controls = [('1.2.840.113556.1.4.319', None, str(control_value))]
        return controls

    def test_send_multiResponse(self):
        client, transport = self.create_test_client()
        op = self.create_test_search_req()
        d = client.send_multiResponse(op, None)
        expected_value = pureldap.LDAPMessage(op)
        expected_value.id -= 1
        expected_bytestring = str(expected_value)
        self.assertEqual(
            transport.value(),
            expected_bytestring)
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0),
            id=expected_value.id)
        resp_bytestring = str(response)
        client.dataReceived(resp_bytestring)
        self.assertEqual(
            response.value,
            self.successResultOf(d))

    def test_send_multiResponse_ex(self):
        client, transport = self.create_test_client()
        op = self.create_test_search_req()
        controls = self.create_paged_search_controls()
        d = client.send_multiResponse_ex(op, controls)
        expected_value = pureldap.LDAPMessage(op, controls)
        expected_value.id -= 1
        expected_bytestring = str(expected_value)
        self.assertEqual(
            transport.value(),
            expected_bytestring)
        resp_controls = self.create_paged_search_controls(0, 'magic')
        response = pureldap.LDAPMessage(
            pureldap.LDAPSearchResultDone(0),
            id=expected_value.id,
            controls=resp_controls)
        resp_bytestring = str(response)
        client.dataReceived(resp_bytestring)
        self.assertEqual(
            (response.value, response.controls),
            self.successResultOf(d))

    def test_send_noResponse(self):
        client, transport = self.create_test_client()
        op = pureldap.LDAPAbandonRequest(id=1)
        client.send_noResponse(op)
