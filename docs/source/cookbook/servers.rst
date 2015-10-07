============
LDAP Servers
============

An LDAP directory information tree (DIT) is a highly specialized
database with entries arranged in a tree-like structure.


""""""""""""""""""""
File-System LDAP DIT
""""""""""""""""""""
A minimal LDAP DIT that stores entries in the local file system

''''
Code
''''

First, a module that defines our DIT entries-- :file:`schema.py`

.. code-block:: python

    #-*-coding:utf-8-*-

    COUNTRY = (
            'dc=fr',
            {
                'objectClass': ['dcObject','country'],
                'dc': ['fr'],
                'description': ["French country 2 letters iso description"],
            }
        )
    COMPANY = (
            'dc=example',
            {
                'objectClass': ['dcObject','organization'],
                'dc': ['example'],
                'description': ["My organisation"],
                'o': ["Example, Inc"],
            }
        )
    PEOPLE = (
            'ou=people',
            {
                'ou': ['people'],
                'description': ['People from Example Inc'],
                'objectclass': ['organizationalunit'],
            }
        )
    USERS = [
                ('uid=yoen', 
                    {
                        'objectClass': ['people', 'inetOrgPerson'],
                        'cn': ['Yoen Van der Weld'],
                        'sn': ['Van der Weld'],
                        'givenName': ['Yoen'],
                        'uid': ['yoen'],
                        'mail': ['/home/yoen/mailDir'],
                        'userPassword': ['secret']
                    }
                ),
                ('uid=esteban', 
                    {
                        'objectClass': ['people', 'inetOrgPerson'],
                        'cn': ['Esteban Garcia Marquez'],
                        'sn': ['Garcia Marquez'],
                        'givenName': ['Esteban'],
                        'uid': ['esteban'],
                        'mail': ['/home/esteban/mailDir'],
                        'userPassword': ['secret2']
                    }
                ),
                ('uid=mohamed', 
                    {
                        'objectClass': ['people', 'inetOrgPerson'],
                        'cn': ['Mohamed Al Ghâlib'],
                        'sn': ['Al Ghâlib'],
                        'givenName': ['mohamed'],
                        'uid': ['mohamed'],
                        'mail': ['/home/mohamed/mailDir'],
                        'userPassword': ['secret3']
                    }
                ),
            ]

Next, the server code-- :file:`fsdit.py`

.. code-block:: python

    #-*-coding:utf-8-*-
    """
        Testing a simple ldaptor ldap server
        Base on an example by Gaston TJEBBES aka "tonthon":
        http://tonthon.blogspot.com/2011/02/ldaptor-ldap-with-twisted-server-side.html
    """
    import tempfile, sys

    from twisted.application import service, internet
    from twisted.internet import reactor
    from twisted.internet.protocol import ServerFactory
    from twisted.python.components import registerAdapter
    from twisted.python import log
    from ldaptor.interfaces import IConnectedLDAPEntry
    from ldaptor.protocols.ldap.ldapserver import LDAPServer
    from ldaptor.ldiftree import LDIFTreeEntry
    from schema import COUNTRY, COMPANY, PEOPLE, USERS


    class Tree(object):

        def __init__(self, path='/tmp'):
            dirname = tempfile.mkdtemp('.ldap', 'test-server', '/tmp')
            self.db = LDIFTreeEntry(dirname)
            self.init_db()

        def init_db(self):
            """
                Add subtrees to the top entry
                top->country->company->people
            """
            country = self.db.addChild(COUNTRY[0], COUNTRY[1])
            company = country.addChild(COMPANY[0], COMPANY[1])
            people = company.addChild(PEOPLE[0], PEOPLE[1])
            for user in USERS:
                people.addChild(user[0], user[1])


    class LDAPServerFactory(ServerFactory):
        """
            Our Factory is meant to persistently store the ldap tree
        """
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
        # When the ldap protocol handle the ldap tree,
        # it retrieves it from the factory adapting
        # the factory to the IConnectedLDAPEntry interface
        # So we need to register an adapter for our factory
        # to match the IConnectedLDAPEntry
        registerAdapter(
            lambda x: x.root,
            LDAPServerFactory,
            IConnectedLDAPEntry)
        # Run it !!
        factory = LDAPServerFactory(tree.db)
        factory.debug = True
        application = service.Application("ldaptor-server")
        myService = service.IServiceCollection(application)
        reactor.listenTCP(port, factory)
        reactor.run()
