"""LDAP protocol proxy server"""

from twisted.internet import reactor, defer
from ldaptor.protocols.ldap import ldapserver, ldapconnector, ldapclient
from ldaptor.protocols import pureldap

class Proxy(ldapserver.BaseLDAPServer):
    protocol = ldapclient.LDAPClient

    client = None
    waitingConnect = []
    unbound = False

    def __init__(self, config):
        """
        Initialize the object.

        @param config: The configuration.
        @type config: ldaptor.interfaces.ILDAPConfig
        """
        ldapserver.BaseLDAPServer.__init__(self)
        self.config = config

    def _whenConnected(self, fn, *a, **kw):
        if self.client is None:
            d = defer.Deferred()
            self.waitingConnect.append((d, fn, a, kw))
            return d
        else:
            return defer.maybeDeferred(fn, *a, **kw)

    def _cbConnectionMade(self, proto):
        self.client = proto
        while self.waitingConnect:
            d, fn, a, kw = self.waitingConnect.pop(0)
            d2 = defer.maybeDeferred(fn, *a, **kw)
            d2.chainDeferred(d)

    def _clientQueue(self, request, controls, reply):
        # TODO controls
        if request.needs_answer:
            d = self.client.send_multiResponse(request, self._gotResponse, reply)
            # TODO handle d errbacks
        else:
            self.client.send_noResponse(request)

    def _gotResponse(self, response, reply):
        reply(response)

        # TODO this is ugly
        return isinstance(response, (
            pureldap.LDAPSearchResultDone,
            pureldap.LDAPBindResponse,
            ))

    def _failConnection(self, reason):
        #TODO self.loseConnection()
        return reason # TODO

    def connectionMade(self):
        clientCreator = ldapconnector.LDAPClientCreator(
            reactor, self.protocol)
        d = clientCreator.connect(
            dn='',
            overrides=self.config.getServiceLocationOverrides())
        d.addCallback(self._cbConnectionMade)
        d.addErrback(self._failConnection)

        ldapserver.BaseLDAPServer.connectionMade(self)

    def connectionLost(self, reason):
        assert self.client is not None
        if self.client.connected:
            if not self.unbound:
                self.client.unbind()
                self.unbound = True
            else:
                self.client.transport.loseConnection()
        self.client = None
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def _handleUnknown(self, request, controls, reply):
        self._whenConnected(self._clientQueue, request, controls, reply)
        return None

    def handleUnknown(self, request, controls, reply):
        d = defer.succeed(request)
        d.addCallback(self._handleUnknown, controls, reply)
        return d

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        self.unbound = True
        self.handleUnknown(request, controls, reply)

if __name__ == '__main__':
    """
    Demonstration LDAP proxy; passes all requests to localhost:389.
    """
    from twisted.internet import protocol
    from twisted.python import log
    import sys
    log.startLogging(sys.stderr)

    factory = protocol.ServerFactory()
    factory.protocol = lambda : Proxy(overrides={
        '': ('localhost', 389),
        })
    reactor.listenTCP(10389, factory)
    reactor.run()
