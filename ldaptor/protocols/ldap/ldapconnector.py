from twisted.internet import utils, protocol, defer
from ldaptor.protocols.ldap import distinguishedname

class LDAPConnector(utils.SRVConnector):
    def __init__(self, reactor, dn, factory,
		 overrides=None):
        if not isinstance(dn, distinguishedname.DistinguishedName):
            dn = distinguishedname.DistinguishedName(stringValue=dn)
        if overrides is None:
            overrides={}
        self.override = self._findOverRide(dn, overrides)

	domain = dn.getDomainName()
	utils.SRVConnector.__init__(self, reactor,
				    'ldap', domain, factory)

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
        """Is there both need and capability to do an SRV query."""
        if self.domain is None:
            # unable to query
            return False

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
	    utils.SRVConnector.connect(self)

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
	    host, port = utils.SRVConnector.pickServer(self)
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
    def connect(self, dn, overrides=None):
        """Connect to remote host, return Deferred of resulting protocol instance."""
        d = defer.Deferred()
        f = protocol._InstanceFactory(self.reactor, self.protocolClass(*self.args, **self.kwargs), d)
        c = LDAPConnector(self.reactor, dn, f, overrides=overrides)
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
