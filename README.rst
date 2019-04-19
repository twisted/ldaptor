Ldaptor
=======

.. image:: https://travis-ci.org/twisted/ldaptor.svg?branch=master
    :target: https://travis-ci.org/twisted/ldaptor

Ldaptor is a pure-Python library that implements:

- LDAP client logic
- separately-accessible LDAP and BER protocol message generation/parsing
- ASCII-format LDAP filter generation and parsing
- LDIF format data generation
- Samba password changing logic

Also included is a set of LDAP utilities for use from the command line.

Verbose documentation can be found on `ReadTheDocs <https://ldaptor.readthedocs.org>`_.


Quick Usage Example
-------------------

.. code-block:: python

    from twisted.internet import reactor, defer
    from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector

    @defer.inlineCallbacks
    def example():
        # The following arguments may be also specified as unicode strings
        # but it is recommended to use byte strings for ldaptor objects
        serverip = b'192.168.128.21'
        basedn = b'dc=example,dc=com'
        binddn = b'bjensen@example.com'
        bindpw = b'secret'
        query = b'(cn=Babs*)'
        c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        overrides = {basedn: (serverip, 389)}
        client = yield c.connect(basedn, overrides=overrides)
        yield client.bind(binddn, bindpw)
        o = ldapsyntax.LDAPEntry(client, basedn)
        results = yield o.search(filterText=query)
        for entry in results:
            print(entry.getLDIF())

    if __name__ == '__main__':
        df = example()
        df.addErrback(lambda err: err.printTraceback())
        df.addCallback(lambda _: reactor.stop())
        reactor.run()


Installation
------------

Ldaptor can be installed using the standard command line method::

    python setup.py install

or using pip from PyPI::

    pip install ldaptor

Linux distributions may also have ready packaged versions of Ldaptor and Twisted. Debian and Ubuntu have quality Ldaptor packages that can be installed e.g., by::

    apt-get install python-ldaptor

To run the LDAP server (bind port 38942) from a repo checkout with
the project installed::

    twistd -n --pidfile=ldapserver.pid --logfile=ldapserver.log \
        -y test-ldapserver.tac

Dependencies:

- `Twisted[tls] <https://pypi.python.org/pypi/Twisted/>`_
- `pyparsing <https://pypi.python.org/pypi/pyparsing/>`_
- `passlib <https://pypi.python.org/pypi/passlib/>`_ for Samba passwords
- `six <https://pypi.python.org/pypi/six/>`_ for simultaneous Python 2 and 3 compatability
- `zope.interface <https://pypi.python.org/pypi/zope.interface/>`_ to register implementers of Twisted interfaces
