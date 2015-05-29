"""LDAP protocol server, which acts as a proxy which
   forwards the requests to multiple LDAP servers and
   merges the results.
   Only Bind and Search requests are supported.
"""

from twisted.internet import reactor, defer
from ldaptor.protocols.ldap import ldapclient, ldapconnector
from ldaptor.protocols.ldap import ldapserver
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols import pureldap
from Queue import Queue
from ldaptor.config import LDAPConfig


class MergedLDAPServer(ldapserver.BaseLDAPServer):
    protocol = ldapclient.LDAPClient

    def __init__(self, configs, use_tls):
        ldapserver.BaseLDAPServer.__init__(self)
        self.clients = []
        self.configs = configs
        self.use_tls = use_tls
        self.all_connected = False
        self.merge_map = {}
        self.waitingConnect = []
        self.unbound = False

    def _whenConnected(self, fn, *a, **kw):
        if not self.all_connected:
            d = defer.Deferred()
            self.waitingConnect.append((d, fn, a, kw))
            return d
        else:
            return defer.maybeDeferred(fn, *a, **kw)

    def _failConnection(self, reason):
        self.transport.loseConnection()
        raise ldaperrors.LDAPOther("Cannot connect to server.{}".format(reason))

    def _cbConnectionMade(self, proto):
        self.clients.append(proto)

        if len(self.clients) == len(self.configs):
            self.all_connected = True

        # Only call once when all clients are connected.
        if self.all_connected:
            while self.waitingConnect:
                d, fn, a, kw = self.waitingConnect.pop(0)
                d2 = defer.maybeDeferred(fn, *a, **kw)
                d2.chainDeferred(d)

    def _clientQueue(self, request, controls, reply):
        # Controls are ignored.
        for c in self.clients:
            if request.needs_answer:
                d = c.send_multiResponse(request, self._gotResponse, reply)
                d.addErrback(defer.logError)
            else:
                c.send_noResponse(request)

    def queue(self, id, op):
        if isinstance(op, (pureldap.LDAPSearchResultDone,
                           pureldap.LDAPBindResponse)):
            if id not in self.merge_map:
                self.merge_map[id] = Queue(len(self.clients))
                self.merge_map[id].put(op)
            else:
                self.merge_map[id].put(op)

            if self.merge_map[id].full():
                # Send success, if at least one success.
                for i in range(len(self.clients)):
                    r = self.merge_map[id].get()
                    if r.resultCode == ldaperrors.Success.resultCode:
                        op = r
                del self.merge_map[id]
                ldapserver.BaseLDAPServer.queue(self, id, op)
        else:
            ldapserver.BaseLDAPServer.queue(self, id, op)

    def connectionMade(self):
        clientCreator = ldapconnector.LDAPClientCreator(
            reactor, self.protocol)
        for (c, tls) in zip(self.configs, self.use_tls):
            d = clientCreator.connect(dn='',
                                      overrides=c.getServiceLocationOverrides())
            if tls:
                d.addCallback(lambda x: x.startTLS())
            d.addCallback(self._cbConnectionMade)
            d.addErrback(self._failConnection)

        ldapserver.BaseLDAPServer.connectionMade(self)

    def connectionLost(self, reason):
        for c in self.clients:
            assert c is not None
            if c.connected:
                if not self.unbound:
                    c.unbind()
                else:
                    c.transport.loseConnection()

        self.clients = []
        self.unbound = True
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def _gotResponse(self, response, reply):
        reply(response)

        # TODO this is ugly
        return isinstance(response, (
            pureldap.LDAPSearchResultDone,
            pureldap.LDAPBindResponse,
            ))

    def _handleUnknown(self, request, controls, reply):
        self._whenConnected(self._clientQueue, request, controls, reply)
        return None

    def handleUnknown(self, request, controls, reply):
        d = defer.succeed(request)
        d.addCallback(self._handleUnknown, controls, reply)
        return d

    def handle_LDAPBindRequest(self, request, controls, reply):
        return self.handleUnknown(request, controls, reply)

    def handle_LDAPSearchRequest(self, request, controls, reply):
        return self.handleUnknown(request, controls, reply)

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        self.unbound = True
        self.handleUnknown(request, controls, reply)

    fail_LDAPDelRequest = pureldap.LDAPDelResponse

    def handle_LDAPDelRequest(self, request, controls, reply):
         raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPAddRequest = pureldap.LDAPAddResponse

    def handle_LDAPAddRequest(self, request, controls, reply):
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPModifyDNRequest = pureldap.LDAPModifyDNResponse

    def handle_LDAPModifyDNRequest(self, request, controls, reply):
         raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPModifyRequest = pureldap.LDAPModifyResponse

    def handle_LDAPModifyRequest(self, request, controls, reply):
        raise ldaperrors.LDAPUnwillingToPerform()

    fail_LDAPExtendedRequest = pureldap.LDAPExtendedResponse

    def handle_LDAPExtendedRequest(self, request, controls, reply):
         raise ldaperrors.LDAPUnwillingToPerform()

if __name__ == '__main__':
    from twisted.internet import protocol
    from twisted.python import log
    import sys
    log.startLogging(sys.stderr)

    configs = [LDAPConfig(serviceLocationOverrides={"": ('localhost', 38942)}),
               LDAPConfig(serviceLocationOverrides={"": ('localhost', 8080)})]
    use_tls = [True, False]
    factory = protocol.ServerFactory()
    factory.protocol = lambda: MergedLDAPServer(configs, use_tls)
    reactor.listenTCP(10389, factory)
    reactor.run()
