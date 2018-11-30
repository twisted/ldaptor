
======================
LDAP Client Quickstart
======================

.. code-block:: python

    from __future__ import print_function

    import sys

    from twisted.internet import defer
    from twisted.internet.endpoints import clientFromString, connectProtocol
    from twisted.internet.task import react
    from ldaptor.protocols.ldap.ldapclient import LDAPClient
    from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry


    @defer.inlineCallbacks
    def onConnect(client):
        # The following arguments may be also specified as unicode strings
        # but it is recommended to use byte strings for ldaptor objects
        basedn = b'dc=example,dc=org'
        binddn = b'cn=bob,ou=people,dc=example,dc=org'
        bindpw = b'secret'
        query = b'(cn=bob)'
        try:
            yield client.bind(binddn, bindpw)
        except Exception as ex:
            print(ex)
            raise
        o = LDAPEntry(client, basedn)
        results = yield o.search(filterText=query)
        for entry in results:
            data = entry.toWire()
            print(data.decode('utf-8'))


    def onError(err):
        err.printDetailedTraceback(file=sys.stderr)


    def main(reactor):
        endpoint_str = "tcp:host=127.0.0.1:port=8080"
        e = clientFromString(reactor, endpoint_str)
        d = connectProtocol(e, LDAPClient())
        d.addCallback(onConnect)
        d.addErrback(onError)
        return d


    react(main)

.. _quickstart-server-label:

=======================
LDAP Server Quick Start
=======================


.. code-block:: python

    import sys
    try:
        from cStringIO import StringIO as BytesIO
    except ImportError:
        from io import BytesIO

    from twisted.application import service
    from twisted.internet.endpoints import serverFromString
    from twisted.internet.protocol import ServerFactory
    from twisted.python.components import registerAdapter
    from twisted.python import log
    from ldaptor.inmemory import fromLDIFFile
    from ldaptor.interfaces import IConnectedLDAPEntry
    from ldaptor.protocols.ldap.ldapserver import LDAPServer


    LDIF = b"""\
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
    gn: Bob
    mail: bob@example.org
    objectclass: top
    objectclass: person
    objectClass: inetOrgPerson
    sn: Roberts
    userPassword: secret

    dn: gn=John+sn=Doe,ou=people,dc=example,dc=org
    objectClass: addressbookPerson
    gn: John
    sn: Doe
    street: Back alley
    postOfficeBox: 123
    postalCode: 54321
    postalAddress: Backstreet
    st: NY
    l: New York City
    c: US
    userPassword: terces

    dn: gn=John+sn=Smith,ou=people, dc=example,dc=org
    objectClass: addressbookPerson
    gn: John
    sn: Smith
    telephoneNumber: 555-1234
    facsimileTelephoneNumber: 555-1235
    description: This is a description that can span multi
     ple lines as long as the non-first lines are inden
     ted in the LDIF.
    userPassword: eekretsay

    """


    class Tree(object):

        def __init__(self):
            global LDIF
            self.f = BytesIO(LDIF)
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
        from twisted.internet import reactor
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
        serverEndpointStr = "tcp:{0}".format(port)
        e = serverFromString(reactor, serverEndpointStr)
        d = e.listen(factory)
        reactor.run()

