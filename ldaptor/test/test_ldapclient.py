"""
Test cases for ldaptor.protocols.ldap.ldapsyntax module.
"""

from twisted.trial import unittest
from twisted.trial import util
from twisted.test import proto_helpers

from ldaptor.protocols.ldap import ldapclient
from twisted.internet import defer
from twisted.python import failure
from twisted.trial.util import deferredResult, deferredError

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

        self.failUnless(d1.called, 'Connection lost must trigger error: %r' % d1)
        self.failUnless(d2.called, 'Connection lost must trigger error: %r' % d2)

        fail = util.deferredError(d1)
        fail.trap(SillyError)

        fail = util.deferredError(d2)
        fail.trap(SillyError)
