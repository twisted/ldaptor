from twisted.trial import unittest, util
from twisted.internet import reactor, protocol, address
from ldaptor.protocols.ldap import ldapconnector, distinguishedname

class FakeProto(protocol.Protocol):
    pass

class TestCallableOverride(unittest.TestCase):
    """
    Callable values in serviceLocationOverride get to override the
    whole connecting process.
    """

    def testSimple(self):
        dn = distinguishedname.DistinguishedName('dc=example,dc=com')
        c = ldapconnector.LDAPClientCreator(reactor, FakeProto)
        def _doConnect(factory):
            factory.doStart()
            factory.startedConnecting(c)
            proto = factory.buildProtocol(address.IPv4Address('TCP', 'localhost', '1'))
        d = c.connect(dn, overrides={ dn: _doConnect, })
        r = util.deferredResult(d)
        self.failUnless(isinstance(r, FakeProto))

    def testFindOverride_plainString(self):
        """Plain strings work as override keys."""
        c=ldapconnector.LDAPConnector(reactor=None,
                                      dn='dc=example,dc=com',
                                      factory=None)
        o=c._findOverRide(dn=distinguishedname.DistinguishedName('cn=foo,dc=example,dc=com'),
                          overrides={
            'dc=example,dc=com': ('server.example.com', 1389),
            })
        self.assertEquals(o, ('server.example.com', 1389))

    def testFindOverride_root(self):
        """Empty dn can be used as override."""
        c=ldapconnector.LDAPConnector(reactor=None,
                                      dn='dc=example,dc=com',
                                      factory=None)
        o=c._findOverRide(dn=distinguishedname.DistinguishedName('cn=foo,dc=example,dc=com'),
                          overrides={
            '': ('server.example.com', 1389),
            })
        self.assertEquals(o, ('server.example.com', 1389))
