"""
Test cases for ldaptor.protocols.ldap.ldapsyntax module.
"""

from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.internet import defer

from ldaptor.protocols.ldap import ldapclient
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
