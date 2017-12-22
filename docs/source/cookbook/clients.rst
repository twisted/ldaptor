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
one-time connection to an LDAP directory listening on the local host, port 8080.
When the deferred returned from that function fires, the connection has
been established and the client protocol instance is passed to the 
:py:func:`onConnect()` callback.

This callback uses inline deferreds to make the syntax more compact.  We create
an :py:class:`ldaptor.protocols.ldap.ldapsyntax.LDAPEntry` with a DN matching
the root of the directory and call the asynchronous :py:func:`search()` method.  The
result returned when the deferred fires is a list of :py:class:`LDAPEntry` 
objects.

When cast as strings, these entries are formatted as LDIF.


""""""""""""""""""""
Adding an LDAP Entry
""""""""""""""""""""

Ldaptor allows your LDAP client make many different kinds of LDAP requests.  In
this example, a simple client connects to an LDAP service and requests adding
an new entry.

''''
Code
''''

.. code-block:: python

    #! /usr/bin/env python

    from __future__ import print_function
    from twisted.internet import reactor, defer
    from twisted.internet.endpoints import clientFromString, connectProtocol
    from twisted.internet.task import react
    from twisted.python import log
    from ldaptor import delta
    from ldaptor.protocols.ldap.ldapclient import LDAPClient
    from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
    from ldaptor.protocols.ldap import ldif
    from ldaptor.protocols import (
        pureber,
        pureldap
    )
    import sys

    @defer.inlineCallbacks
    def onConnect(client, entry):
        # Convert simple key-value pairs into the structure we need for the
        # LDAP Add request.
        attribs = {}
        dn = None
        for attrib, value in entry.items():
            if attrib == 'dn':
                dn = value
                continue
            attribs.setdefault(attrib, set([])).add(value)
        if dn is None:
            raise Exception("Template needs to include `dn`!")
        ldap_attrs = []
        for attrib, values in attribs.items():
            ldap_attrib_type = pureldap.LDAPAttributeDescription(attrib)
            l = []
            for value in values:
                if (isinstance(value, unicode)):
                    value = value.encode('utf-8')
                l.append(pureldap.LDAPAttributeValue(value))
            ldap_values = pureber.BERSet(l)
            ldap_attrs.append((ldap_attrib_type, ldap_values))
        # Once we have the DN of the new entry and the attributes, make the
        # request.
        op = pureldap.LDAPAddRequest(
            entry=str(dn),
            attributes=ldap_attrs)
        print("LDAP Add request: {}".format(repr(op)))
        response = yield client.send(op)
        print(repr(response))

    def onError(err, reactor):
        if reactor.running:
            log.err(err)
            reactor.stop()

    def main(reactor):
        log.startLogging(sys.stdout)
        entry = {
            "dn": "gn=Jane+sn=Doe,ou=people,dc=example,dc=org",
            "c": "US",
            "gn": "Jane",
            "l": "Philadelphia",
            "objectClass": "addressbookPerson",
            "postalAddress": "230",
            "postalCode": "314159",
            "sn": "Doe",
            "st": "PA",
            "street": "Mobius Strip",
            "userPassword": "terces",
        }
        endpoint_str = "tcp:host=localhost:port=8080"
        e = clientFromString(reactor, endpoint_str)
        d = connectProtocol(e, LDAPClient())
        d.addCallback(onConnect, entry)
        d.addErrback(onError, reactor)
        return d

    react(main)


''''''''''
Discussion
''''''''''

Once again, the :py:func:`twisted.internet.task.react()` function is used
to call the `main()` function of the client.  When `main()` is called, we 
create a client endpoint from a string description and the reactor.
:py:func:`twisted.internet.endpoints.connectProtocol()` is used to make a
one-time connection to an LDAP directory listening on the local host, port 8080.

When the deferred returned from that function fires, the connection has
been established and the client protocol instance is passed to the 
:py:func:`onConnect()` callback, along with our entry.  

In this case we use a simple Python dictionary to model our entry. We need to
transform this into a data structure that
:py:class:`ldaptor.protocols.pureldap.LDAPAddRequest` can use.  Once we've 
created the request, it is relatively simple to send it to the directory
service with a call to the `send()` method of our client.  The response will
indicate either success or failure.






