"""LDAP protocol proxy server"""

from ldaptor import config
from ldaptor.protocols.ldap import ldapserver, ldapconnector, ldapclient, ldaperrors
from ldaptor.protocols import pureldap
from twisted.internet import reactor, defer
from twisted.python import log


class ProxyBase(ldapserver.BaseLDAPServer):
    protocol = ldapclient.LDAPClient
    client = None
    unbound = False
    clientCreator = ldapconnector.LDAPClientCreator

    def __init__(self, config, use_tls=False, reactor_=reactor):
        """
        Initialize the object.

        @param config: The configuration.
        @type config: ldaptor.interfaces.ILDAPConfig

        @param use_tls: Force connections to the proxied server to use startTLS.
        @type use_tls: boolean
        """
        ldapserver.BaseLDAPServer.__init__(self)
        self.config = config
        # Requests that are ready before the client connection is established
        # are queued.
        self.queuedRequests = []
        self.use_tls = use_tls
        self.reactor = reactor_

    def connectionMade(self):
        # Esablish a connection to the proxied LDAP server.
        clientCreator = self.clientCreator(self.reactor, self.protocol)
        d = clientCreator.connect(
            dn='',
            overrides=self.config.getServiceLocationOverrides())
        d.addCallback(self._connectedToProxiedServer)
        d.addErrback(self._failedToConnectToProxiedServer)

        ldapserver.BaseLDAPServer.connectionMade(self)

    def connectionLost(self, reason):
        if self.client is not None and self.client.connected:
            if not self.unbound:
                self.client.unbind()
                self.unbound = True
            else:
                self.client.transport.loseConnection()
        self.client = None
        ldapserver.BaseLDAPServer.connectionLost(self, reason)

    def _connectedToProxiedServer(self, proto):
        """
        The connection to the proxied server is set up.
        """
        if self.use_tls:
            d = proto.startTLS()
            d.addCallback(self._establishedTLS)
            return d
        else:
            self.client = proto
            self._processBacklog()

    def _establishedTLS(self, proto):
        """
        TLS has been started.
        Process any backlog of requests.
        """
        self.client = proto
        self._processBacklog()

    def _failedToConnectToProxiedServer(self, err):
        """
        The connection to the proxied server failed.
        """
        log.err(err)
        return err 

    def _processBacklog(self):
        """
        Process the backlog of requests.
        """
        while len(self.queuedRequests) > 0:
            request, controls, reply = self.queuedRequests.pop(0)
            self._forwardRequestToProxiedServer(request, controls, reply)

    def _forwardRequestToProxiedServer(self, request, controls, reply):
        """
        Forward the original requests to the proxied server.
        """
        if self.client is None:
            self.queuedRequests.append((request, controls, reply))
            return

        def forwardit(result, reply):
            """
            Forward the LDAP request to the proxied server.
            """
            request, controls = result
            if request.needs_answer:
                d = self.client.send_multiResponse(request, self._gotResponseFromProxiedServer, reply, request, controls)
                d.addErrback(log.err)
                del d
            else:
                self.client.send_noResponse(request)
        d = defer.maybeDeferred(self.handleBeforeForwardRequest, request, controls)
        d.addCallback(forwardit, reply)

    def handleBeforeForwardRequest(self, request, controls):
        """
        Override to modify request and/or controls forwarded on to the proxied server.
        Must return a tuple of request, controls or a deferred that fires the same.
        """
        return defer.succeed((request, controls))

    def _gotResponseFromProxiedServer(self, response, reply, request, controls):
        """
        Returns True if this is the last response to the request.
        """
        d = defer.maybeDeferred(self.handleProxiedResponse, response, request, controls)
        d.addCallback(reply)

        # Evaluate to True if this is the last response to the request.
        return isinstance(response, (
            pureldap.LDAPSearchResultDone,
            pureldap.LDAPBindResponse,
            ))

    def handleProxiedResponse(self, response, request, controls):
        """
        Override to intercept and modify proxied responses.
        Must return the modified response or a deferred that fires the modified response.
        """
        return defer.succeed(response)

    def handleUnknown(self, request, controls, reply):
        d = defer.succeed(request)
        d.addCallback(self._forwardRequestToProxiedServer, controls, reply)
        return d

    def handle_LDAPExtendedRequest(self, request, controls, reply):
        """
        """
        log.msg("Received extended request: " + request.requestName)
        if request.requestName == pureldap.LDAPStartTLSRequest.oid:
            d = defer.maybeDeferred(self.handleStartTLSRequest, request, controls, reply)
            d.addErrback(log.err)
            return d

        return self.handleUnknown(request, controls, reply)

    def handleStartTLSRequest(self, request, controls, reply):
        """
        """
        log.msg("Received startTLS request: " + repr(request)) 
        msg = pureldap.LDAPStartTLSResponse(resultCode=ldaperrors.LDAPUnavailable.resultCode)
        log.msg("StartTLS not implemented.  Responding with 'unavailable' (52): " + repr(msg))
        #self.transport.write(msg)
        return defer.succeed(msg)
        

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        self.unbound = True
        self.handleUnknown(request, controls, reply)

class MyProxy(ProxyBase):
    """
    """
    def handleProxiedResponse(self, response, request, controls):
        """
        Log the representation of the responses received.
        """
        log.msg("Received response from proxied service: " + repr(response))
        return defer.succeed(response)

if __name__ == '__main__':
    """
    Demonstration LDAP proxy; passes all requests to localhost:389.
    """
    from twisted.internet import protocol
    import sys
    log.startLogging(sys.stderr)

    factory = protocol.ServerFactory()
    proxied = ('localhost', 8080)
    use_tls = False
    cfg = config.LDAPConfig(serviceLocationOverrides={ '': proxied, })
    factory.protocol = lambda : MyProxy(cfg, use_tls=use_tls)
    reactor.listenTCP(10389, factory)
    reactor.run()

