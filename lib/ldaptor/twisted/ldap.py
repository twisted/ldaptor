from twisted.python import defer
from ldaptor.protocols import ldapclient
import authorizer, identity

class LDAPIdentity(identity.Identity, ldapclient.LDAPClient):
    def __init__(self, name, application):
        ldapclient.LDAPClient.__init__(self)
        identity.Identity.__init__(self, name, application)
        # TODO map name to dn?
        self.dn=name

    def setPassword(self, plaintext):
        raise NotImplementedError()
    def setAlreadyHashedPassword(self, cyphertext):
        raise NotImplementedError()
    def challenge(self):
        raise NotImplementedError()

    def connectionMade(self):
        #self.bind(self.dn, self.auth)
        pass

    def connectionLost(self):
        pass

    def handle_bind_success(self, matchedDN, serverSaslCreds):
        pass

class LDAPAuthorizer(authorizer.Authorizer):
    def __init__(self, host="localhost", port=389):
        authorizer.Authorizer.__init__(self)
        self.host=host
        self.port=port

    def getIdentityRequest(self, name):
        """Get an identity request, make the given callback when it's received.

        Override this to provide a method for retrieving identities than
        the hash provided by default. The method should return a Deferred.

        Note that this is asynchronous specifically to provide support
        for authenticating users from a database.
        """
        req = defer.Deferred()
        i = LDAPIdentity(name, self.application)
        tcp.Client(self.host, self.port, i)
        req
        if self.identities.has_key(name):
            req.callback(self.identities[name])
        else:
            req.errback("unauthorized")
