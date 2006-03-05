# -*- python -*-
from zope.interface import implements
from twisted.application import service, internet
from nevow import appserver, inevow, tags
from ldaptor import config
from ldaptor.apps.webui import main, i18n, defskin

application = service.Application("ldaptor-webui")
myService = service.IServiceCollection(application)

class DemoSkin(defskin.DefaultSkin):
    def render_content(self, ctx, data):
        return tags.invisible[
            tags.div(style="float: right; color: lightgray; font-size: 5em;")['demo'],
            super(DemoSkin, self).render_content(ctx, data),
            ]

resource = main.getResource(skinFactory=DemoSkin)

class Wrap(object):
    implements(inevow.IResource)

    def __init__(self, resource):
        super(Wrap, self).__init__()
        self.resource = resource

    def locateChild(self, ctx, segments):
        ctx.remember(i18n.I18NConfig(localeDir='build/locale'))
        ctx.remember(['fi'], i18n.ILanguages)
        return self.resource, segments

    def renderHTTP(self, ctx):
        ctx.remember(i18n.I18NConfig(localeDir='build/locale'))
        ctx.remember(['fi'], i18n.ILanguages)
        return self.resource.renderHTTP(ctx)

site = appserver.NevowSite(Wrap(resource))

myServer = internet.TCPServer(38980, site)
myServer.setServiceParent(myService)
