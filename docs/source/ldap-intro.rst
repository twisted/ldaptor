====================
Introduction to LDAP
====================

Foreword
--------

This text is intended as a quick introduction to the interesting bits of the LDAP protocol, and should be useful whether you are managing an LDAP server, programming something using an LDAP library, or writing an LDAP library yourself.
I welcome any feedback you might have.

LDAP Presents a Distributed Tree of Information
-----------------------------------------------

Probably the nicest way to get a mental model of LDAP information is to think of a tree with elements both in leaf and non-leaf nodes.
Parts of the tree may reside at different LDAP servers.

.. image::  _static/images/ldap-is-a-tree.png
   :alt: Tree-like, distributed nature of data stored in LDAP

An organization normally uses their DNS domain name as the root entry for their local LDAP tree.
For example, ``example.com`` is free to use ``dc=example,dc=com``.
The ``dc`` stands for ``domainComponent``.
An alternative is to identify the organization via geographical location, as in ``o=Example Inc., c=US``, but this is cumbersome as it requires registration to avoid name conflicts.
The ``o`` stands for organization, ``c`` for country.
You will also encounter ``ou``, short for organizational unit.

Each node of the tree is called an "LDAP entry", and can contain multiple attributes in the form of attributeType=value pairs, for example ``surname=Wiesel``.
One attributeType may appear multiple times, in effect having multiple values.

One or more of the attributes are chosen as a Relative Distinguished Name or RDN, and will be used to identify the node based on its parent.
This means the RDN must be unique among the children of its parent.
Listing all the RDNs, separated by commas, from the node to the root, gives us the Distinguished Name or DN of the entry.

- The RDN of the entry for Jack E. Wiesel is ``cn=Jack E. Wiesel``.
- The DN is ``cn=Jack E. Wiesel,ou=Sales,ou=People,dc=example,dc=com``.
- The ``cn`` is short for common name.

The RDN of the entry for John Doe consist of two attributes, ``gn=John`` and ``sn=Doe``, joined with a plus sign to form ``gn=John+sn=Doe``.
``gn`` is short for given name (first name), ``sn`` for surname (last name).

Objectclasses and Schemas
-------------------------

A special attributeType of ``objectClass`` lists all the objectclasses the LDAP entry manifests.
An object class basically lists what attribute types an entry must have, and what optional attribute types it may have.
For example, telephone directory entries must have a name and a telephone number, and may have a fax number and street address.
``objectClass`` can have multiple values, allowing the same entry to describe e.g. information about a person both for a telephone directory and for UNIX shell login.

An LDAP schema is a part of the configuration of the LDAP server, containing two things: definitions of attribute types and definitions of objectclasses.
It is normally stored as ASCII text, but can e.g. be requested from the server over an LDAP connection.

An attribute type definition commonly contains a global identifier for the attribute type (a list of period-separated integers), a list of names for the attribute type, a free-form description and a reference to another attribute type this definition inherits from.
It may also contain information about what sort of data the attribute values may contain, how to compare and sort them, how to find substrings in the value, whether the attribute type can have multiple values, etc.

An example attributeType definition::

    attributetype ( 2.5.4.4 NAME ( 'sn' 'surname' )
    DESC 'RFC2256: last (family) name(s) for which the entity is known by'
    SUP name )

An object class definition also commonly contains a global identifier, name, description and inheritance information.
It also commonly lists the attribute types entries having this object class must have, and additional attribute types they may have.
An entry cannot have attribute types that are not listed as a ``MUST`` or ``MAY`` by one of the entrys object classes or their parents.

An example objectClass definition::

    objectclass ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person'
    SUP top STRUCTURAL MUST ( sn $ cn ) MAY
    ( userPassword $ telephoneNumber $ seeAlso $ description ) )

There are a lot of pre-existing schemas, standardized in various RFCs.
Also, anyone can create their own schemas.
The only things you need are access to the LDAP server configuration, and a number reserved for you, which can be achieved by filling a web form.

Object-oriented look at LDAP entries
------------------------------------

If you look at LDAP entries from the viewpoint of a programmer accustomed with object oriented programming, you will see a lot of similarities, but also some striking differences.

Writing Things Down: LDIF
-------------------------

There is a standardized way of writing down, in plain text, the contents of LDAP directories, individual entries and even add, delete and modify operations.
This format is known as LDIF (LDAP Data Interchange Format) LDAP Data Interchange Format, and it is defined in RFC2849.

The rough format of LDIF is this: there is a paragraph per entry, where paragraphs are separated by blank lines.
Each paragraph contains lines in the format keyword:value.
Entries start by listing the keyword ``dn``, and their DN, and then list all the attributes and values the entry has.
Lines starting with space are appended to the previous line.
The whole file starts with the keyword version and value 1.

.. NOTE::
   The actual format is more complex, but this tutorial
   should allow you to read and write normal LDIF files fluently.

A simple LDAP file with two entries::

    version: 1
    dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
    objectclass: top
    objectclass: person
    objectclass: organizationalPerson
    cn: Barbara Jensen
    cn: Barbara J Jensen
    cn: Babs Jensen
    sn: Jensen
    uid: bjensen
    telephonenumber: +1 408 555 1212
    description: A big sailing fan.

    dn: cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com
    objectclass: top
    objectclass: person
    objectclass: organizationalPerson
    cn: Bjorn Jensen
    sn: Jensen
    telephonenumber: +1 408 555 1212


A file containing an entry with a folded ``description`` attribute value, from `RFC 2849 <https://www.ietf.org/rfc/rfc2849.html#page-8>`_::

    version: 1
    dn:cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
    objectclass:top
    objectclass:person
    objectclass:organizationalPerson
    cn:Barbara Jensen
    cn:Barbara J Jensen
    cn:Babs Jensen
    sn:Jensen
    uid:bjensen
    telephonenumber:+1 408 555 1212
    description:Babs is a big sailing fan, and travels extensively in sea
     rch of perfect sailing conditions.
    title:Product Manager, Rod and Reel Division

Searches and Search Filters
---------------------------

The most common LDAP operation is a search, and LDAP is purposefully designed for environments where searches are many times more common than modify operations.
In general, LDAP servers index the entries and can effectively search for matches against a reasonably complex criteria among thousands of entries.

An LDAP search takes the following information as input:

* base DN
* scope (base, one level, subtree)
* filter
* attributes requested

.. NOTE::
   Once again, we are skipping some details for
   understandability.

Of these, the search filter is clearly the most interesting one.
As with LDIF, search filters have a standardized plain text representation, even though they are not transmitted as plain text in the actual protocol.

A search filter is basically a combination of tests an entry must fulfill in order to match the filter.
They are always written inside parentheses.
A simple example would be

::

    (cn=John Smith)

but the filters can also match against presence, prefix, suffix, substring, rough equality, etc.
Multiple matches can be combined freely with and, or and not operators, which are represented by ``&``, ``|`` and ``!``, respectively.
For example, to match only objects that have objectClass ``person``, where the full name contains the letters a and b in either order, and who don't have a telephone number listed, we could use the filter

.. NOTE::
   Yes, once again we are skipping details for understandability. See RFC2254 for more.

``(&(objectClass=person)(!(telephoneNumber=*))(|(cn=*a*b*)(cn=*b*a*)))``

.. image:: _static/images/ldapfilter-as-tree.png
   :alt: Visualizing an LDAP search filter

Phases of an LDAP Protocol Chat
-------------------------------

An average LDAP protocol chat consists of three stages:

#. Opening the connection
#. Doing one or more searches
#. Closing the connection

At the first stage, opening a connection, an LDAP client opens a TCP connection to the LDAP server, either as plain text, encrypted by TLS or starting with plaintext and switching to use TLS with STARTTLS.

The client authenticates itself and/or the user, providing any necessary authentication information.
This is called binding.
Normally, the connection is not really authenticated, but left as anonymous; the bind message is sent with no user or password information.

.. image:: _static/images/chat-bind.png
   :alt: Beginning of an LDAP protocol chat

Next, the client sends a search request, containing the base DN for the search, the filter that entries must fulfill to match, and some extra settings discussed above.

The server replies by sending search result entries back, one message per matching entry.
If no entry matched or there was an error before the search could even start, the server might not send any entries.
Finally, the server sends a message indicating the search is done, and includes information on whether the search was completely successfully, or the error encountered.

.. image:: _static/images/chat-search.png
   :alt: A sample LDAP search operation

Note that the client could have sent another search request without waiting for the first search to complete.
The order of results from the different search, or when they are completed, is in no way guaranteed.

.. image:: _static/images/chat-search-pipeline.png
   :alt: Multiple search operations pipelined

One important detail we have skimmed over so far is how the LDAP client knows what message the server is replying to.
Earlier we avoided this topic just by doing only one thing at a time, but now we have two searches getting their result entries interleaved.
Clearly, there must be a mechanism to separate which entries belong to which search request.
And exactly such a mechanism exists; each message sent by the client contains a number identifying the request, and the server replies by including the same number in the reply.
Now, all the client needs to do is remember which numbers are still in use, and not reuse those.
It can internally maintain search state based on these numbers, and process result entries based on them.
The client can reuse a number when it is known that no more server replies will be sent using that number; for example, the search done message gives this guarantee.

Finally, when the client no longer wants to talk to the server, it sends a message effectively saying 
"good bye".  This message is known as ``unbind``.
This only means that the state of connection is the same as when connected, before the first ``bind``; that is, it un-authenticates the current user.
If the client really wants to close the connection, it will then close the TCP socket.

.. image:: _static/images/chat-unbind.png
   :alt: End of an LDAP protocol chat

Please understand that these were just examples, and in reality protocol chats are often more complicated.
For example, one could connect some other protocol servers, say a web servers, authentication mechanism to actually act as an LDAP client, that tries to bind as the user authenticating himself to the web server, with the password given by the user.
If this service had no other interest in the contents of LDAP, it would probably immediately after the bind close the connection.
But opening and closing TCP connections repeatedly is slow; it is quite likely the authentication mechanism would be changed to keep a single TCP connection alive, and just do repeated binds over the same connection.
