from twisted.cred import checkers, credentials, error
from twisted.internet import defer, reactor
from twisted.python import failure
from ldaptor import ldapfilter, config
from ldaptor.protocols.ldap import ldapconnector, ldapclient, ldapsyntax

def makeFilter(name, template=None):
    filter=None
    try:
        filter=ldapfilter.parseFilter(name)
    except ldapfilter.InvalidLDAPFilter:
        try:
            filter=ldapfilter.parseFilter('('+name+')')
        except ldapfilter.InvalidLDAPFilter:
            if template is not None:
                try:
                    filter=ldapfilter.parseFilter(template % {'name':name})
                except ldapfilter.InvalidLDAPFilter:
                    pass
    return filter

class LDAPBindingChecker:
    """

    The avatarID returned is an LDAPEntry.

    """

    __implements__ = checkers.ICredentialsChecker
    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, cfg):
        self.config = cfg

    def _valid(self, result, entry):
        matchedDN, serverSaslCreds = result
        return entry

    def _found(self, results, credentials):
        if not results:
            return failure.Failure(error.UnauthorizedLogin('TODO 1'))
        assert len(results)==1
        entry = results[0]
        d = entry.client.bind(str(entry.dn), credentials.password)
        d.addCallback(self._valid, entry)
        return d

    def _connected(self, client, filt, credentials):
        base = ldapsyntax.LDAPEntry(client, self.config.getIdentityBaseDN())
        d = base.search(filterObject=filt,
                        sizeLimit=1,
                        attributes=[''], # TODO no attributes
                        )
        d.addCallback(self._found, credentials)
        return d

    def requestAvatarId(self, credentials):
        try:
            baseDN = self.config.getIdentityBaseDN()
        except config.MissingBaseDNError, e:
            return failure.Failure(error.UnauthorizedLogin("Disabled due configuration error: %s." % e))
        if not credentials.username:
            return failure.Failure(error.UnauthorizedLogin("I don't support anonymous"))
        filtText = self.config.getIdentitySearch(credentials.username)
        try:
            filt = ldapfilter.parseFilter(filtText)
        except ldapfilter.InvalidLDAPFilter:
            return failure.Failure(error.UnauthorizedLogin("Couldn't create filter"))

	c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
	d = c.connect(baseDN, self.config.getServiceLocationOverrides())
        d.addCallback(self._connected, filt, credentials)
        return d
