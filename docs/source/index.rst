Welcome to Ldaptor's documentation!
===================================

What is Ldaptor
---------------

Ldaptor is a pure-Python Twisted library that implements:

* LDAP client logic
* separately-accessible LDAP and BER protocol message generation/parsing
* ASCII-format LDAP filter generation and parsing
* LDIF format data generation

Quick Usage Example
-------------------

.. code-block:: python

    python
    from twisted.internet import reactor, defer
    from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector

    @defer.inlineCallbacks
    def example():
        serverip = '192.168.128.21'
        basedn = 'dc=example,dc=com'
        binddn = 'bjensen@example.com'
        bindpw = 'secret'
        query = '(cn=Babs*)'
        c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        overrides = {basedn: (serverip, 389)}
        client = yield c.connect(basedn, overrides=overrides)
        yield client.bind(binddn, bindpw)
        o = ldapsyntax.LDAPEntry(client, basedn)
        results = yield o.search(filterText=query)
        for entry in results:
            print entry

    if __name__ == '__main__':
        df = example()
        df.addErrback(lambda err: err.printTraceback())
        df.addCallback(lambda _: reactor.stop())
        reactor.run()


User Guide
----------

.. toctree::
   :maxdepth: 2

   AUTHORS
   ldap-intro

.. toctree::
   :maxdepth: 1

   NEWS
   addressbook-example

Ldaptor API:
------------

.. toctree::
   :maxdepth: 1

   ldaptor


Status and History
==================

Ldaptor was created by Tommi Virtanen (tv42) who developed it during the years 2001-2008.
From 2007 and onwards mainly bug fixes were added, many contributed by Debian maintainers.
Development picked back up in 2014 by Bret Curtis (psi29a) with Tommi's consent and was migrated
to Twisted where it is a first-party Twisted library. Ldaptor can be found here:

`<https://github.com/twisted/ldaptor>`_

The LDAP client library functionality is in active use. It is stable and works very well.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

