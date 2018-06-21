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
        log.msg("LDIF formatted results:\n{}".format(f.getvalue()))

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

.. code-block:: python

    #! /usr/bin/env python

    from __future__ import print_function
    import argparse
    from twisted.internet import defer
    from twisted.internet.endpoints import clientFromString, connectProtocol
    from twisted.internet.task import react
    from ldaptor.protocols.ldap.ldapclient import LDAPClient
    from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
    from ldaptor.protocols import (
        pureber,
        pureldap
    )
    import sys

    @defer.inlineCallbacks
    def onConnect(client, args):
        binddn = args.bind_dn
        bindpw = args.passwd_file.read().strip()
        if args.start_tls:
            yield client.startTLS()
        try:
            yield client.bind(binddn, bindpw)
        except Exception as ex:
            print(ex)
            raise
        page_size = args.page_size
        cookie = ''
        page = 1
        count = 0
        while True:
            results, cookie = yield process_entry(
                client, 
                args, 
                args.filter, 
                page_size=page_size,
                cookie=cookie)
            count += len(results)
            print("Page {}".format(page))
            display_results(results)
            if len(cookie) == 0:
                break
            page += 1
        print("There were {} results returned in total.".format(count))

    @defer.inlineCallbacks
    def process_entry(client, args, search_filter, page_size=100, cookie=''):
        basedn = args.base_dn
        control_value = pureber.BERSequence([
            pureber.BERInteger(page_size),
            pureber.BEROctetString(cookie),
        ])
        controls = [('1.2.840.113556.1.4.319', None, control_value)]
        o = LDAPEntry(client, basedn)
        results, resp_controls  = yield o.search(
            filterText=search_filter,
            attributes=['dn'],
            controls=controls,
            return_controls=True)
        cookie = get_paged_search_cookie(resp_controls)
        defer.returnValue((results, cookie))

    def display_results(results):
        for entry in results:
            print(entry.dn)

    def get_paged_search_cookie(controls):
        """
        Input: semi-parsed controls list from LDAP response; list of tuples (controlType, criticality, controlValue).
        Parses the controlValue and returns the cookie as a byte string.
        """
        control_value = controls[0][2]
        ber_context = pureber.BERDecoderContext()
        ber_seq, bytes_used = pureber.berDecodeObject(ber_context, control_value)
        raw_cookie = ber_seq[1]
        cookie = raw_cookie.value
        return cookie 

    def onError(err):
        err.printDetailedTraceback(file=sys.stderr)

    def main(reactor, args):
        endpoint_str = args.endpoint
        e = clientFromString(reactor, endpoint_str)
        d = connectProtocol(e, LDAPClient())
        d.addCallback(onConnect, args)
        d.addErrback(onError)
        return d

    if __name__ == "__main__":
        parser = argparse.ArgumentParser(description="AD LDAP demo.")
        parser.add_argument(
            "endpoint",
            action="store",
            help="The Active Directory service endpoint.  See https://twistedmatrix.com/documents/current/core/howto/endpoints.html#clients")
        parser.add_argument(
            "bind_dn",
            action="store",
            help="The DN to BIND to the service as.")
        parser.add_argument(
            "passwd_file",
            action="store",
            type=argparse.FileType('r'),
            help="A file containing the password used to log into the service.")
        parser.add_argument(
            "base_dn",
            action="store",
            help="The base DN to start from when searching.")
        parser.add_argument(
            "-f",
            "--filter",
            action='store',
            help='LDAP filter')
        parser.add_argument(
            "-p",
            "--page-size",
            type=int,
            action='store',
            default=100,
            help='Page size (default 100).')
        parser.add_argument(
            "--start-tls",
            action="store_true",
            help="Request StartTLS after connecting to the service.")
        args = parser.parse_args()
        react(main, [args])

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
    from twisted.internet import reactor, defer
    from twisted.internet.endpoints import clientFromString, connectProtocol
    from twisted.internet.task import react
    from twisted.python import log
    from ldaptor.protocols.ldap.ldapclient import LDAPClient
    from ldaptor.protocols import (
        pureber,
        pureldap
    )
    import sys

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
                if (isinstance(value, unicode)):
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
            "dn": "gn=Jane+sn=Doe,ou=people,dc=example,dc=fr",
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






