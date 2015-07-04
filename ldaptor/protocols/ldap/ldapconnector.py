from twisted.internet import protocol, defer
from twisted.internet.endpoints import clientFromString, connectProtocol
from ldaptor.protocols.ldap import distinguishedname
try:
    from twisted.internet.utils import SRVConnector
except ImportError:
    from twisted.names.srvconnect import SRVConnector

def connectToLDAPEndpoint(reactor, endpointStr, clientProtocol):
    e = clientFromString(reactor, endpointStr)
    d = connectProtocol(e, clientProtocol())
    return d


class LDAPConnector(SRVConnector):
    def __init__(self, reactor, dn, factory,
                 overrides=None, bindAddress=None):
        if not isinstance(dn, distinguishedname.DistinguishedName):
            dn = distinguishedname.DistinguishedName(stringValue=dn)
        if overrides is None:
            overrides={}
        self.override = self._findOverRide(dn, overrides)

        domain = dn.getDomainName()
        SRVConnector.__init__(self, reactor,
                  'ldap', domain, factory,
                  connectFuncKwArgs={'bindAddress': bindAddress})

    def __getstate__(self):
        r={}
        r.update(self.__dict__)
        r['connector'] = None
        return r

    def _findOverRide(self, dn, overrides):
        while True:
            if overrides.has_key(dn):
                return overrides[dn]
            if dn == '':
                break
            dn = dn.up()
        return None

    def _isQueryNeeded(self):
        """Is there both need to do an SRV query."""
        if self.override is None:
            return True

        assert not callable(self.override)
        overriddenHost, overriddenPort = self.override
        if overriddenHost is None:
            return True
        if overriddenPort is not None:
            return False
        return True

    def connect(self):
        if callable(self.override):
            self.override(self.factory)
        elif not self._isQueryNeeded():
            self.factory.doStart()
            self.factory.startedConnecting(self)
            self._reallyConnect()
        else:
            SRVConnector.connect(self)

    def pickServer(self):
        if self.override is None:
            overriddenHost, overriddenPort = None, None
        else:
            overriddenHost, overriddenPort = self.override

        if (overriddenHost is not None
            and (overriddenPort is not None
                 or self.domain is None)):
            host = overriddenHost
            port = overriddenPort
        else:
            host, port = SRVConnector.pickServer(self)
            if overriddenHost is not None:
                host = overriddenHost
            if overriddenPort is not None:
                port = overriddenPort

        try:
            port = int(port)
        except ValueError:
            pass

        assert host is not None
        if port is None:
            port = 389
        return host, port

class LDAPClientCreator(protocol.ClientCreator):
    def connect(self, dn, overrides=None, bindAddress=None):
        """Connect to remote host, return Deferred of resulting protocol instance."""
        d = defer.Deferred()
        f = protocol._InstanceFactory(self.reactor, self.protocolClass(*self.args, **self.kwargs), d)
        c = LDAPConnector(self.reactor, dn, f, overrides=overrides,
                bindAddress=bindAddress)
        c.connect()
        return d

    def connectAnonymously(self, dn, overrides=None):
        """Connect to remote host and bind anonymously, return Deferred of resulting protocol instance."""
        d = self.connect(dn, overrides=overrides)

        def _bind(proto):
            d=proto.bind()
            d.addCallback(lambda _: proto)
            return d
        d.addCallback(_bind)
        return d
