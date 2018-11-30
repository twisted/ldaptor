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

    import sys
    try:
        from cStringIO import StringIO as BytesIO
    except ImportError:
        from io import BytesIO

    from ldaptor.protocols.ldap.ldapclient import LDAPClient
    from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
    from twisted.internet.defer import inlineCallbacks
    from twisted.internet.endpoints import clientFromString, connectProtocol
    from twisted.internet.task import react
    from twisted.python import log


    @inlineCallbacks
    def onConnect(clientProtocol):
        o = LDAPEntry(clientProtocol, "dc=org")
        resultList = yield o.search()
        f = BytesIO()
        for result in resultList:
            f.write(result.toWire())
            f.write(b"\n")
        data = f.getvalue()
        log.msg(u"LDIF formatted results:\n{}".format(data.decode("utf-8")))


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

""""""""""""""""""""""""""""""""""""""""""""""
Searching with the Paged Search Result Control
""""""""""""""""""""""""""""""""""""""""""""""

.. todo:: This example should be made Python 3 compatible

Some :term:`DITs` place limits on the number of entries they are willing to
return as the result of a LDAP SEARCH request.  Microsoft's Active Directory
is one such service.  In order to query and process large result sets, you
can use the paged result control (OID 1.2.840.113556.1.4.319) if you DIT
supports it.

The paged result control allows you to request a particular page size.  The
:term:`DIT` will return a response control that has a magic cookie if the
there are additional pages of results.  You can use the cookie on a new
request to process the results one page at a time.

''''
Code
''''

For `ad.example.com` domain, store the admin password in a file named
`pass_file` and run the following example,
where `10.20.1.2` is replaced with the IP of your AD server, and ::

    python docs/source/cookbook/client_paged_search_results.py \
        tcp:host=10.20.1.2:port=389 \
        'CN=Administrator,CN=Users,DC=ad,DC=example,DC=com' \
        pass_file \
        'CN=Users,DC=ad,DC=example,DC=com' \
        --page-size 5

The output should look like::

    Page 1
    b'CN=Users,DC=ad,DC=example,DC=com'
    b'CN=Administrator,CN=Users,DC=ad,DC=example,DC=com'
    b'CN=Guest,CN=Users,DC=ad,DC=example,DC=com'
    b'CN=SUPPORT_388945a0,CN=Users,DC=ad,DC=example,DC=com'
    b'CN=HelpServicesGroup,CN=Users,DC=ad,DC=example,DC=com'
    Page 2
    b'CN=TelnetClients,CN=Users,DC=ad,DC=example,DC=com'
    b'CN=krbtgt,CN=Users,DC=ad,DC=example,DC=com'
    b'CN=Domain Computers,CN=Users,DC=ad,DC=example,DC=com'
    There were 8 results returned in total.


.. literalinclude:: client_paged_search_results.py
   :language: python
   :emphasize-lines: 41, 67-77
   :linenos:


''''''''''
Discussion
''''''''''

On connecting to the LDAP service, our client establishes TLS and BINDs as a DN
that has permission to perform a search.  Page, cookie, and the result count
are intialized before looping to process each page.  Initially, a blank cookie
is used in the search request.  The cookie obtained from each response is used
in the next request, until the cookie is blank.  This signals the end of the
loop.

Note how the search returns a tuple of results *and* controls from the LDAP
response.  This is because the `return_controls` flag of the search was set
to `True`.

Parsing the cookie requires some :term:`BER` decoding.  For details on encoding
of the control value, refer to `RFC 2696 <https://tools.ietf.org/html/rfc2696>`_.

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

    import sys

    from twisted.internet import defer
    from twisted.internet.endpoints import clientFromString, connectProtocol
    from twisted.internet.task import react
    from twisted.python import log
    from ldaptor.protocols.ldap.ldapclient import LDAPClient
    from ldaptor.protocols import pureber, pureldap

    try:
        str_type = unicode
    except NameError:
        str_type = str


    def entry_to_attribs_(entry):
        """
        Convert a simple mapping to the data structures required for an
        entry in the DIT.

        Returns: (dn, attributes)
        """
        attribs = {}
        dn = None
        for prop, value in entry.items():
            if prop == 'dn':
                dn = value
                continue
            attribs.setdefault(prop, set([])).add(value)
        if dn is None:
            raise Exception("Entry needs to include key, `dn`!")
        ldap_attrs = []
        for attrib, values in attribs.items():
            ldap_attrib_type = pureldap.LDAPAttributeDescription(attrib)
            l = []
            for value in values:
                if (isinstance(value, str_type)):
                    value = value.encode('utf-8')
                l.append(pureldap.LDAPAttributeValue(value))
            ldap_values = pureber.BERSet(l)
            ldap_attrs.append((ldap_attrib_type, ldap_values))
        return dn, ldap_attrs


    @defer.inlineCallbacks
    def onConnect(client, entry):
        dn, attributes = entry_to_attribs_(entry)
        op = pureldap.LDAPAddRequest(
            entry=str(dn),
            attributes=attributes)
        response = yield client.send(op)
        resultCode = response.resultCode
        if response.resultCode != 0:
            errorMessage = response.errorMessage
            log.err(
                "DIT reported error code {}: {}".format(resultCode, errorMessage))


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
one-time connection to a LDAP directory listening on the local host, port 8080.

When the deferred returned from that function fires, the connection has
been established and the client protocol instance is passed to the 
:py:func:`onConnect()` callback, along with our entry.  

In this case we use a simple Python dictionary to model our entry. We need to
transform this into a data structure that
:py:class:`ldaptor.protocols.pureldap.LDAPAddRequest` can use.  Once we've 
created the request, it is relatively simple to send it to the directory
service with a call to the `send()` method of our client.  The response will
indicate either success or failure.






