Creating a simple LDAP application
==================================

Author: Tommi Virtanen <tv@debian.org>

Updated: 2004-06-09

LDAP presents a distributed tree of information
-----------------------------------------------
.. image::  ldap-is-a-tree.png

Writing things down: LDIF
=========================
    addressbook-ldif/doe.xml

Writing things down: LDIF
=========================

    addressbook-ldif/smith.xml


Setting up an LDAP server in 5 seconds
======================================

Python, an easy programming language
------------------------------------

**Batteries included!**
    
Python combines remarkable power with very clear syntax.

Runs on many brands of UNIX, on Windows, OS/2, Mac, Amiga, 
and many other platforms.

The first step
==============
    addressbook-session/session-01.xml

Ldaptor
-------

Ldaptor is a set of pure-Python LDAP client programs, 
applications and a programming library.

It is licensed under the MIT (Expat) License.

Overview of Ldaptor
-------------------

.. image::  overview.png

Preparing to connect
====================
    addressbook-session/session-02.xml

Twisted
-------

Twisted is an event-driven networking framework written in Python 
and licensed under the MIT (Expat) License.

Twisted supports TCP, UDP, SSL/TLS, multicast, Unix sockets,
a large number of protocols (including HTTP, NNTP, SSH, IRC, FTP,
and others), and much more.

Twisted includes many fullblown applications, such as web,
SSH, FTP, DNS and news servers.

Connecting
==========
    addressbook-session/session-03.xml

Deferreds
---------

* A promise that a function will at some point have a result.
* You can attach callback functions to a Deferred.
* Once it gets a result these callbacks will be called.
* Also allows you to register a callback for an error, with the
    default behavior of logging the error.
* Standard way to handle all sorts of blocking or delayed operations.

Searching
=========
    addressbook-session/session-04.xml

Results
=======

    addressbook-session/session-05.xml

Results one-by-one
==================

    addressbook-session/session-06.xml

LDIF output
===========

    addressbook-session/session-07.xml

Closing the connection
======================

    addressbook-session/session-08.xml

Access to entry details
=======================

    addressbook-session/session-09.xml

Object-oriented look at LDAP entries
====================================

A lot of similarities with OO programming languages, but some big differences, too.

:doc:`ldapentry-vs-oo`

Search inputs
=============
:doc:`search-inputs`

An example search filter: ``(cn=John Smith)``

Our first Python program
========================

    02_script/addressbook-py.html

Phases of the protocol chat
---------------------------
* Open and bind
* Search (possibly many times)
* Unbind and close

Opening and binding
-------------------
.. image::  chat-bind.png

Doing a search
--------------
.. image::  chat-search.png

Doing multiple searches
-----------------------
.. image::  chat-search-pipeline.png

Unbinding and closing
---------------------
.. image::  chat-unbind.png

A complex search filter
=======================
An example::

    (&(objectClass=person)
        (!(telephoneNumber=*))
        (|(cn=*a*b*)(cn=*b*a*)))

.. image::  ldapfilter-as-tree.png

Objectclasses
=============

#. Special attribute ``objectClass`` lists all the objectclasses an LDAP entry manifests.
#. Objectclass defines
    #. What attributetypes an entry MUST have
    #. What attributetypes an entry MAY have
#. An entry in a phonebook must have a name and a telephone number,
    and may have a fax number and street address.

Schema
======
#. A configuration file included in the LDAP server configuration.
#. A combination of attribute type and object class definitions.
#. Stored as plain text
#. Can be requested over an LDAP connection

Attribute type
==============
An example::

    attributetype ( 2.5.4.4 NAME ( 'sn' 'surname' )
        DESC 'RFC2256: last (family) name(s) for which the entity is known by'
        SUP name )


Can also contain:
#. content data type
#. comparison and sort mechanism
#. substring search mechanism
#. whether multiple values are allowed

Object class
============

An example::

    objectclass ( 2.5.6.6 NAME 'person'
        DESC 'RFC2256: a person'
        SUP top STRUCTURAL
        MUST ( sn $ cn )
        MAY ( userPassword $ telephoneNumber
        $ seeAlso $ description )
    )

Creating schemas
================
#. Anyone can create their own schema
#. Need to be globally unique
#. But try to use already existing ones

Where to go from here?
======================

Install OpenLDAP: http://www.openldap.org/

Install Ldaptor: https://github.com/twisted/ldaptor

Learn Python: http://www.python.org/

Learn Twisted. Write a client application for a simple protocol. Read the HOWTOs.
http://twistedmatrix.com/documents/howto/clients


Thank You
=========

Questions?