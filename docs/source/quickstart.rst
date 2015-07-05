
======================
LDAP Client Quickstart
======================

.. code-block:: python

    from __future__ import print_function
    from twisted.internet import reactor, defer
    from twisted.internet.endpoints import clientFromString, connectProtocol
    from twisted.internet.task import react
    from ldaptor.protocols.ldap.ldapclient import LDAPClient
    from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry

    @defer.inlineCallbacks
    def onConnect(client):
        basedn = 'dc=example,dc=org'
        binddn = 'cn=bob,ou=people,dc=example,dc=org'
        bindpw = 'secret'
        query = '(cn=bob)'
        try:
            yield client.bind(binddn, bindpw)
        except Exception as ex:
            print(ex)
            raise
        o = LDAPEntry(client, basedn)
        results = yield o.search(filterText=query)
        for entry in results:
            print(entry)

    def onError(err, reactor):
        err.printTraceback()

    def main(reactor):
        endpoint_str = "tcp:host=127.0.0.1:port=8080"
        e = clientFromString(reactor, endpoint_str)
        d = connectProtocol(e, LDAPClient())
        d.addCallback(onConnect)
        d.addErrback(onError, reactor)
        return d

    react(main)

=======================
LDAP Server Quick Start
=======================


.. code-block:: python

    from twisted.application import service, internet
    from twisted.internet import reactor
    from twisted.internet.protocol import ServerFactory
    from twisted.python.components import registerAdapter
    from twisted.python import log
    from ldaptor.inmemory import fromLDIFFile
    from ldaptor.interfaces import IConnectedLDAPEntry
    from ldaptor.protocols.ldap import distinguishedname
    from ldaptor.protocols.ldap.ldapserver import LDAPServer
    import tempfile
    from cStringIO import StringIO
    import sys

    LDIF = """\
    dn: dc=org
    dc: org
    objectClass: dcObject

    dn: dc=example,dc=org
    dc: example
    objectClass: dcObject
    objectClass: organization

    dn: ou=people,dc=example,dc=org
    objectClass: organizationalUnit
    ou: people

    dn: cn=bob,ou=people,dc=example,dc=org
    cn: bob
    givenName: Bob
    mail: bob@example.org
    objectclass: top
    objectclass: person
    objectClass: inetOrgPerson
    sn: Roberts

    """


    class Tree(object):

        def __init__(self):
            global LDIF
            self.f = StringIO(LDIF)
            d = fromLDIFFile(self.f)
            d.addCallback(self.ldifRead)

        def ldifRead(self, result):
            self.f.close()
            self.db = result

    class LDAPServerFactory(ServerFactory):
        protocol = LDAPServer

        def __init__(self, root):
            self.root = root

        def buildProtocol(self, addr):
            proto = self.protocol()
            proto.debug = self.debug
            proto.factory = self
            return proto

    if __name__ == '__main__':
        if len(sys.argv) == 2:
            port = int(sys.argv[1])
        else:
            port = 8080
        # First of all, to show logging info in stdout :
        log.startLogging(sys.stderr)
        # We initialize our tree
        tree = Tree()
        # When the LDAP Server protocol wants to manipulate the DIT, it invokes
        # `root = interfaces.IConnectedLDAPEntry(self.factory)` to get the root
        # of the DIT.  The factory that creates the protocol must therefore
        # be adapted to the IConnectedLDAPEntry interface.
        registerAdapter(
            lambda x: x.root,
            LDAPServerFactory,
            IConnectedLDAPEntry)
        factory = LDAPServerFactory(tree.db)
        factory.debug = True
        application = service.Application("ldaptor-server")
        myService = service.IServiceCollection(application)
        reactor.listenTCP(port, factory)
        reactor.run()
