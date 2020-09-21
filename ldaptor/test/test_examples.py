"""
Tests for the code from docs/source/example.
"""
import os
import sys

from twisted.test import proto_helpers
from twisted.trial import unittest

from ldaptor import inmemory
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols import pureldap

# We inject the examples so that we can import them.
# There is no cleanup, so this is leaving side effects.
sys.path.append(os.path.abspath("docs/source/examples"))
import ldaptor_with_upn_bind


class LDAPServerWithUPNBind(unittest.TestCase):
    """
    Tests for docs/source/examples/ldaptor_with_upn_bind.py
    """

    def setUp(self):
        self.root = inmemory.ReadOnlyInMemoryLDAPEntry(
            dn='dc=example,dc=com',
            attributes={'dc': 'example'})
        self.user = self.root.addChild(
            rdn=b'cn=bob',
            attributes={
                'objectClass': ['a', 'b'],
                # Hash is for "secret".
                'userPassword': [b'{SSHA}yVLLj62rFf3kDAbzwEU0zYAVvbWrze8='],
                'userPrincipalName': ['bob@ad.example.com'],
            })

        server = ldaptor_with_upn_bind.LDAPServerWithUPNBind()
        server.factory = self.root
        server.transport = proto_helpers.StringTransport()
        server.connectionMade()
        self.server = server

    def checkSuccessfulBIND(self, bind_dn, password):
        """
        Do a BIND request and check that is succeeds.
        """
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn=bind_dn,
                    auth=password),
                id=4).toWire()
        )
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=0,
                    matchedDN='cn=bob,dc=example,dc=com'),
                id=4).toWire()
        )

    def test_bindSuccessUPN(self):
        """
        It can authenticate based on the UPN.
        """
        self.checkSuccessfulBIND('bob@ad.example.com', b'secret')


    def test_bindSuccessDN(self):
        """
        It can still authenticate based on the normal DN.
        """
        self.checkSuccessfulBIND('cn=bob,dc=example,dc=com', b'secret')


    def test_bindBadPassword(self):
        """
        When password don't match the BIND fails.
        """
        self.server.dataReceived(
            pureldap.LDAPMessage(
                pureldap.LDAPBindRequest(
                    dn='bob@ad.example.com',
                    auth='invalid'),
                id=734).toWire()
        )
        self.assertEqual(
            self.server.transport.value(),
            pureldap.LDAPMessage(
                pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPInvalidCredentials.resultCode),
                id=734).toWire()
        )
