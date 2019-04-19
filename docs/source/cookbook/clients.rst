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

.. literalinclude:: /examples/client_basic.py
   :language: python
   :linenos:


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
where `10.20.1.2` is replaced with the IP of your AD server::

    python docs/source/cookbook/client_paged_search_results.py \
        tcp:host=10.20.1.2:port=389 \
        'CN=Administrator,CN=Users,DC=ad,DC=example,DC=com' \
        pass_file \
        'CN=Users,DC=ad,DC=example,DC=com' \
        --page-size 5

The output should look like::

    Page 1
    CN=Users,DC=ad,DC=example,DC=com
    CN=Administrator,CN=Users,DC=ad,DC=example,DC=com
    CN=Guest,CN=Users,DC=ad,DC=example,DC=com
    CN=SUPPORT_388945a0,CN=Users,DC=ad,DC=example,DC=com
    CN=HelpServicesGroup,CN=Users,DC=ad,DC=example,DC=com
    Page 2
    CN=TelnetClients,CN=Users,DC=ad,DC=example,DC=com
    CN=krbtgt,CN=Users,DC=ad,DC=example,DC=com
    CN=Domain Computers,CN=Users,DC=ad,DC=example,DC=com
    There were 8 results returned in total.


.. literalinclude:: /examples/client_paged_search_results.py
   :language: python
   :emphasize-lines: 39, 68-79
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

.. literalinclude:: /examples/client_add_ldap_entry.py
   :language: python
   :linenos:


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






