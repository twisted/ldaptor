from twisted.internet import utils, protocol, defer
from ldaptor.protocols.ldap import distinguishedname

class LDAPConnector(utils.SRVConnector):
    def __init__(self, reactor, dn, factory,
		 overrides=None):
	assert isinstance(dn, distinguishedname.DistinguishedName)
        if overrides is None:
            overrides={}
	self.overriddenHost, self.overriddenPort = self._findOverRide(dn, overrides)

	domain = dn.getDomainName()
	utils.SRVConnector.__init__(self, reactor,
				    'ldap', domain, factory)

    def __getstate__(self):
        r={}
        r.update(self.__dict__)
        r['connector'] = None
        return r

    def _findOverRide(self, dn, overrides):
	while dn != distinguishedname.DistinguishedName(stringValue=''):
	    if overrides.has_key(str(dn)):
		return overrides[str(dn)]
	    dn = dn.up()
	return None, None

    def connect(self):
	if (self.overriddenHost is not None
	    and (self.overriddenPort is not None
		 or self.domain is None)):
	    # no need to query or unable to query
	    self.factory.doStart()
	    self.factory.startedConnecting(self)
	    self._reallyConnect()
	else:
	    utils.SRVConnector.connect(self)

    def pickServer(self):
	if (self.overriddenHost is not None
	    and (self.overriddenPort is not None
		 or self.domain is None)):
	    host = self.overriddenHost
	    port = self.overriddenPort
	else:
	    host, port = utils.SRVConnector.pickServer(self)
	    if self.overriddenHost is not None:
		host = self.overriddenHost
	    if self.overriddenPort is not None:
		port = self.overriddenPort

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
