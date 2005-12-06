# -*- python -*-
from twisted.application import service, internet
from twisted.internet import protocol
from twisted.python import components
from twisted.trial import util
from ldaptor import ldiftree, interfaces
from ldaptor.protocols.ldap import ldapserver

db = ldiftree.LDIFTreeEntry('ldaptor/test/ldif/webtests')

class LDAPServerFactory(protocol.ServerFactory):
    protocol = ldapserver.LDAPServer

    def __init__(self, root):
        self.root = root

ldapserver.LDAPServer.debug = True

components.registerAdapter(lambda x: x.root,
                           LDAPServerFactory,
                           interfaces.IConnectedLDAPEntry)


application = service.Application("ldaptor-server")
myService = service.IServiceCollection(application)

factory = LDAPServerFactory(db)

myServer = internet.TCPServer(10389, factory)
myServer.setServiceParent(myService)
