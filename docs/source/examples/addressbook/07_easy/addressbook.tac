# -*- python -*-
from twisted.application import service, internet

import addressbook

config = addressbook.LDAPConfig(
    baseDN="ou=People,dc=example,dc=com",
    serviceLocationOverrides={
        "dc=example,dc=com": ("localhost", 10389),
    },
)

application = service.Application("LDAPressBook")
site = addressbook.getSite(config)
webServer = internet.TCPServer(8088, site)
webServer.setServiceParent(application)
