"""LDAP protocol proxy server"""

from twisted.internet import reactor, defer
from ldaptor.protocols.ldap import ldapserver, ldapconnector, ldapclient
from ldaptor.protocols import pureldap

class Proxy(ldapserver.BaseLDAPServer):
    client = None
    waitingConnect = []
    protocol = ldapclient.LDAPClient

    def __init__(self, overrides):
        ldapserver.BaseLDAPServer.__init__(self)
        self.overrides=overrides

    def _cbConnectionMade(self, proto):
        self.client = proto
        while self.waitingConnect:
            request, controls, handler = self.waitingConnect.pop(0)
            self._clientQueue(request, controls, handler)

    def _clientQueue(self, request, controls, handler):
        # TODO controls
        if request.needs_answer:
            self.client.queue(request, self._gotReply, handler)
        else:
            self.client.queue(request)

    def _gotReply(self, reply, handler):
        handler(reply)
        return isinstance(reply, (
            pureldap.LDAPSearchResultDone,
            pureldap.LDAPBindResponse,
            ))

    def _failConnection(self, reason):
        #TODO self.loseConnection()
        return reason # TODO

    def connectionMade(self):
        clientCreator = ldapconnector.LDAPClientCreator(
            reactor, self.protocol)
        d = clientCreator.connect(dn='', overrides=self.overrides)
        d.addCallback(self._cbConnectionMade)
        d.addErrback(self._failConnection)

        ldapserver.BaseLDAPServer.connectionMade(self)

    def connectionLost(self, reason):
        assert self.client is not None
        if self.client.connected:
            self.client.unbind()
        self.client = None
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def _handleUnknown(self, request, controls, handler):
        if self.client is None:
            self.waitingConnect.append((request, controls, handler))
        else:
            self._clientQueue(request, controls, handler)
        return None

    def handleUnknown(self, request, controls, handler):
        d = defer.succeed(request)
        d.addCallback(self._handleUnknown, controls, handler)
        return d


if __name__ == '__main__':
    """
    Demonstration LDAP proxy; passes all requests to localhost:389.
    """
    from twisted.internet import reactor, protocol
    from twisted.python import log
    import sys
    log.startLogging(sys.stderr)

    factory = protocol.ServerFactory()
    factory.protocol = lambda : Proxy(overrides={
        '': ('localhost', 389),
        })
    reactor.listenTCP(10389, factory)
    reactor.run()
