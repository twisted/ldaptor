# -*- python -*-
from twisted.application import service, internet
from nevow import appserver, inevow
from ldaptor import config
from ldaptor.apps.webui import main, i18n

application = service.Application("ldaptor-webui")
myService = service.IServiceCollection(application)

resource = main.getResource()

class Wrap(object):
    __implements__ = inevow.IResource,

    def __init__(self, resource):
        super(Wrap, self).__init__()
        self.resource = resource

    def locateChild(self, ctx, segments):
        ctx.remember(i18n.I18NConfig(localeDir='locale'))
        ctx.remember(['fi'], i18n.ILanguages)
        return self.resource, segments

    def renderHTTP(self, ctx):
        ctx.remember(i18n.I18NConfig(localeDir='locale'))
        ctx.remember(['fi'], i18n.ILanguages)
        return self.resource.renderHTTP(ctx)

site = appserver.NevowSite(Wrap(resource))

myServer = internet.TCPServer(38980, site)
myServer.setServiceParent(myService)
