# -*- python -*-
from twisted.application import service, internet
from nevow import appserver
from ldaptor import config
from ldaptor.apps.webui import main

application = service.Application("ldaptor-webui")
myService = service.IServiceCollection(application)

resource = main.getResource()

site = appserver.NevowSite(resource)

myServer = internet.TCPServer(38980, site)
myServer.setServiceParent(myService)
