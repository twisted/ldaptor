Ldaptor
=======

Ldaptor is a pure-Python library that implements:

- LDAP client logic
- separately-accessible LDAP and BER protocol message
  generation/parsing
- ASCII-format LDAP filter generation and parsing
- LDIF format data generation
- Samba password changing logic

Also included is a web-based user interface to search and edit
information in an LDAP directory and a set of LDAP utilities for use
from the command line.


Quick Usage Example
-------------------

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

Ldaptor can be installed using the standard command line method:

    python setup.py install

Your maintainer recommends [virtualenv](http://pypi.python.org/pypi/virtualenv) 
so you don't need to be root and so you can update to the latest Twisted
libraries without disturbing other Python programs.

Linux distributions may also have ready packaged versions of Ldaptor and
Twisted. Debian and Ubuntu have quality Ldaptor packages that
can be installed e.g., by:

    apt-get install python-ldaptor


To run the LDAP server (runs on port 38942):

    twistd -ny --pidfile=ldapserver.pid --logfile=ldapserver.log \
        test-ldapserver.tac

To run the web interface (runs on port 38980):

    twistd -ny --pidfile=webui.pid --logfile=webui.log test-webui.tac

Dependencies:

- [Twisted](http://pypi.python.org/pypi/Twisted/)
- [pyparsing](http://pypi.python.org/pypi/pyparsing/)
- [pyOpenSSL](http://pypi.python.org/pypi/pyOpenSSL/)
- [PyCrypto](http://pypi.python.org/pypi/pycrypto/) for Samba passwords

Additional dependencies for the web UI:

- [Nevow](http://pypi.python.org/pypi/Nevow/)
- [webut](http://github.com/antong/webut)


Status and History
==================

Ldaptor was created by Tommi Virtanen who developed it during the
years 2001-2008. From 2007 onwards mainly bug fixes were added, many
contributed by Debian maintainers. The original author is however no
longer developing or actively using Ldaptor. The currently maintained
code directly descends from the original author's code repository
available at:

- http://eagain.net/gitweb/?p=ldaptor.git
- git://eagain.net/ldaptor.git

The LDAP client library functionality is in active use. It is stable
and works very well. Current focus is on fixing bugs and maintaining
compatibility with new, stable Python and Twisted releases.

The web UI is not maintained and, to the maintainer's knowledge,
not actively used. It can be made to run, but relies on deprecated
functionality in Twisted.


