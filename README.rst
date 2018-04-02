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


Installation
------------

Ldaptor can be installed using the standard command line method::

    python setup.py install

or using pip from PyPI::

    pip install ldaptor

Linux distributions may also have ready packaged versions of Ldaptor and Twisted. Debian and Ubuntu have quality Ldaptor packages that can be installed e.g., by::

    apt-get install python-ldaptor

To run the LDAP server (runs on port 38942)::

    twistd -ny --pidfile=ldapserver.pid --logfile=ldapserver.log \
        test-ldapserver.tac

Dependencies:

- `Twisted <https://pypi.python.org/pypi/Twisted/>`_
- `pyparsing <https://pypi.python.org/pypi/pyparsing/>`_
- `pyOpenSSL <https://pypi.python.org/pypi/pyOpenSSL/>`_
- `PyCrypto <https://pypi.python.org/pypi/pycrypto/>`_ for Samba passwords
