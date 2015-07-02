============
LDAP Clients
============

The following recipies demonstrate asynchronous LDAP clients.

""""""""""""""""""""""""""""""""
A Minimal Client Using Endpoints
""""""""""""""""""""""""""""""""

While Ldaptor exposes helper classes to connect clients to the DIT,
it is possible to use the Twisted *endpoints* API to connect an Ldaptor
client to a server.

''''
Code
''''

.. code-block:: python

    #! /usr/bin/env python

    from ldaptor.protocols.ldap.ldapclient import LDAPClient
    from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
    from twisted.internet.defer import inlineCallbacks, returnValue
    from twisted.internet.endpoints import clientFromString, connectProtocol
    from twisted.internet.task import react
    from twisted.python import log
    from cStringIO import StringIO
    import sys

    @inlineCallbacks
    def onConnect(clientProtocol):
        o = LDAPEntry(clientProtocol, "dc=org")
        resultList = yield o.search()
        f = StringIO()
        for result in resultList:
            f.write(str(result))
            f.write("\n")
        log.msg("LDIF formatted results:\n{0}".format(f.getvalue()))

    def onError(err, reactor):
        if reactor.running:
            log.err(err)
            reactor.stop()

    def main(reactor):
        log.startLogging(sys.stdout)
        endpoint_str = "tcp:host=localhost:port=8080"
        e = clientFromString(reactor, endpoint_str)
        d = connectProtocol(e, LDAPClient())
        d.addCallback(onConnect)
        d.addErrback(onError, reactor)
        return d

    react(main)

''''''''''
Discussion
''''''''''

The :py:func:`twisted.internet.task.react()` function is perfect for running a
one-shot `main()` function.  When `main()` is called, we create a client 
endpoint from a string description and the reactor.
:py:func:`twisted.internet.endpoints.connectProtocol()` is used to make a
one-time connection to an LDAP DIT listening on the local host, port 8080.
When the deferred returned from that function fires, the connection has
been established and the client protocol instance is passed to the 
:py:func:`onConnect()` callback.

This callback uses inline deferreds to make the syntax more compact.  We create
an :py:class:`ldaptor.protocols.ldap.ldapsyntax.LDAPEntry` with a DN matching
the root of the DIT and call the asynchronous :py:func:`search()` method.  The
result returned when the deferred fires is a list of :py:class:`LDAPEntry` 
objects.

When cast as strings, these entries are formatted as LDIF.

