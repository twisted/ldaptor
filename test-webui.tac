# -*- python -*-
from twisted.application import service, internet
from nevow import appserver, inevow
from ldaptor import config
from ldaptor.apps.webui import main, i18n

application = service.Application("ldaptor-webui")
myService = service.IServiceCollection(application)

cp = config.loadConfig(configFiles=[])
cp.add_section('webui')
cp.set('webui', 'search-field 1 Name',
       '(|(cn=%(input)s)(uid=%(input)s))')
cp.add_section('authentication')
cp.set('authentication', 'identity-base',
       'dc=example,dc=com')

cfg = config.LDAPConfig(serviceLocationOverrides={
    'dc=example,dc=com': ('localhost', 10389),
    })
resource = main.getResource(cfg)

site = appserver.NevowSite(resource)

myServer = internet.TCPServer(38980, site)
myServer.setServiceParent(myService)
