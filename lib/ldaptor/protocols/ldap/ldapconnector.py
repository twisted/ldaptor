from twisted.internet import utils
from ldaptor.protocols.ldap import distinguishedname

class LDAPConnector(utils.SRVConnector):
    def __init__(self, reactor, dn, factory,
		 overrides={}):
	assert isinstance(dn, distinguishedname.DistinguishedName)
	self.overriddenHost, self.overriddenPort = self._findOverRide(dn, overrides)

	domain = dn.getDomainName()
	utils.SRVConnector.__init__(self, reactor,
				    'ldap', domain, factory)

    def _findOverRide(self, dn, overrides):
	while dn != distinguishedname.DistinguishedName(stringValue=''):
	    if overrides.has_key(dn):
		return overrides[dn]
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
