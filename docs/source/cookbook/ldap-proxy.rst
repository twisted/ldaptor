====================
Create an LDAP Proxy
====================

An LDAP proxy sits between an LDAP client and an LDAP server.  It accepts LDAP 
requests from the client and forwards them to the LDAP server.  Responses from
the server are then relayed back to the client.

----------------
Why is it Useful
----------------

An LDAP proxy has many different uses:

* If a client does not natively support LDAP over SSL or StartTLS, a proxy
  can be run on the client host.  The client can interact with the proxy
  which can use LDAPS or StartTLS when communicating with the backend
  service.
* When troubleshooting LDAP connections between LDAP clients and servers,
  it can be useful to determine what kinds of requests and responses
  are passing between the client and server.  Sometimes, access to client
  or server logs is not available or not helpful.  By logging the interactions
  at the proxy, one can gain insight into what requests are being made by the
  client and what responses the server makes.
* It may be desirable to provide limited access to an LDAP service.  For 
  example, it may be desirable to grant an application search access to an 
  LDAP DIT, but any Modify, Add, or Delete operations are not allowed.  A
  proxy can be configured to disable those particular LDAP operations.
* LDAP requests can be modified before sending them on to the LDAP server.
  For example, the base DN of search could be transparently modified based
  on the current BIND user.
* Similarly, LDAP responses from the server can be modified before sending 
  them to the client.  For example, search results could be populated with
  computed attributes, or a domain could be appended to any returned `uid`
  attribute.
* The proxy can be configured to connect to one of several LDAP servers
  (replicas).  This can be an effective technique when a particular LDAP
  client library shows affinity for a particular host in an LDAP replica
  round-robin architecture.  The client can be configured to always connect
  to the proxy, which in turn will distrbute the connections amongst the 
  replicas.

--------
Examples
--------

""""""""""""""""""
Logging LDAP Proxy
""""""""""""""""""

.. code-block:: python

    from ldaptor import config
    from ldaptor.protocols import pureldap
    from ldaptor.protocols.ldap.proxybase import ProxyBase
    from twisted.internet import defer, protocol, reactor
    from twisted.python import log
    import sys

    class LoggingProxy(ProxyBase):
        """
        A simple example of using `ProxyBase` to log requests and responses.
        """
        def handleProxiedResponse(self, response, request, controls):
            """
            Log the representation of the responses received.
            """
            log.msg("Request => " + repr(request))
            log.msg("Response => " + repr(response))
            return defer.succeed(response)

    def ldapBindRequestRepr(self):
        l=[]
        l.append('version={0}'.format(self.version))
        l.append('dn={0}'.format(repr(self.dn)))
        l.append('auth=****')
        if self.tag!=self.__class__.tag:
            l.append('tag={0}'.format(self.tag))
        l.append('sasl={0}'.format(repr(self.sasl)))
        return self.__class__.__name__+'('+', '.join(l)+')'

    pureldap.LDAPBindRequest.__repr__ = ldapBindRequestRepr

    if __name__ == '__main__':
        """
        Demonstration LDAP proxy; passes all requests to localhost:10389.
        """
        log.startLogging(sys.stderr)
        factory = protocol.ServerFactory()
        proxied = ('localhost', 8080)
        use_tls = False
        cfg = config.LDAPConfig(serviceLocationOverrides={'': proxied, })
        factory.protocol = lambda : LoggingProxy(cfg, use_tls=use_tls)
        reactor.listenTCP(10389, factory)
        reactor.run()

The main idea in the above program is to subclass 
`ldaptor.protocols.ldap.proxybase.ProxyBase` and override its
`handleProxiedResponse()` method.

The function `ldapBindRequestRepr()` is used to patch the __repr__ magic method
of the `ldaptor.protocols.pureldap.LDAPBindRequest` class.  The representation
normally prints the BIND password, which is typically *not* what you want.

The main program entry point starts logging and creates a generic server factory.
The proxied LDAP server is configured to be running on the local host on port 8080.
The factory protocol is set to a function that takes no arguments and returns an
instance of our `LoggingProxy` that has been configured with te proxied LDAP server 
settings.  The Twisted reactor is then configured to listen on TCP port 10389 and
use te factory to create protocol instances to handle incoming connections.

The `ProxyBase` class handles the typical LDAP protocol events but provides convenient
hooks for intercepting LDAP requests and responses.  In this proxy, we wait until
we have a reponse and log both the request and the respone.  in the case of a search
request with multiple responses, the request is repeatedly displayed with each response.

