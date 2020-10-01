# -*- python -*-
import shutil
from twisted.application import service, internet
from twisted.internet import protocol
from twisted.python import components
from ldaptor import ldiftree, interfaces
from ldaptor.protocols.ldap import ldapserver

DBPATH = "ldaptor/test/ldif/webtests"
TMPDBPATH = "%s.tmp" % DBPATH
shutil.rmtree(TMPDBPATH, ignore_errors=True)
shutil.copytree(DBPATH, TMPDBPATH)
db = ldiftree.LDIFTreeEntry(TMPDBPATH)


class LDAPServerFactory(protocol.ServerFactory):
    protocol = ldapserver.LDAPServer

    def __init__(self, root):
        self.root = root


ldapserver.LDAPServer.debug = True

components.registerAdapter(
    lambda x: x.root, LDAPServerFactory, interfaces.IConnectedLDAPEntry
)


application = service.Application("ldaptor-server")
myService = service.IServiceCollection(application)

factory = LDAPServerFactory(db)

myServer = internet.TCPServer(38942, factory)
myServer.setServiceParent(myService)
