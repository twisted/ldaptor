Welcome to Ldaptor's documentation!
===================================

What is Ldaptor
---------------

Ldaptor is a pure-Python Twisted library that implements:

- LDAP client logic
- separately-accessible LDAP and BER protocol message generation/parsing
- ASCII-format LDAP filter generation and parsing
- LDIF format data generation

Get it from `PyPI <https://pypi.python.org/pypi/Ldaptor>`_, find out what's new in the :doc:`NEWS`!

Quick Usage Example
-------------------

.. code-block:: python

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


User's Guide
------------

.. toctree::
   :maxdepth: 1

   ldap-intro
   addressbook-example
   cookbook/*
   ldaptor

Meta
----

.. toctree::
   :maxdepth: 1

   NEWS
   status
   AUTHORS

Indices and tables
==================

- :ref:`genindex`
- :ref:`modindex`
- :ref:`search`
