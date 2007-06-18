import os
from zope.interface import implements
from webut.skin import iskin
from nevow import rend, loaders, tags, util, static
from formless import webform

class DefaultSkin(rend.Page):
    implements(iskin.ISkin)

    docFactory = loaders.xmlfile(
        util.resource_filename('ldaptor.apps.webui', 'skin-default.html'))

    stylesheets = [
        'form.css',
        'ldaptor.css',
        ]

    def locateChild(self, ctx, segments):
        if segments[0] == 'form.css':
            return webform.defaultCSS, segments[1:]
        if segments[0] == 'ldaptor.css':
            dirname = os.path.abspath(os.path.dirname(__file__))
            return (static.File(os.path.join(dirname, 'ldaptor.css')),
                    segments[1:])
        else:
            return None, ()

    def render_title(self, ctx, data):
        return ctx.tag.clear()[self.original.resource.title]

    def render_head(self, ctx, data):
        def links(l, path=None):
            for filename in l:
                href = filename
                if path is not None:
                    href = path.child(href)
                yield tags.link(rel="stylesheet",
                                type="text/css",
                                href=href)
        ctx.tag.clear()
        stylesheets = getattr(self, 'stylesheets', None)
        if stylesheets is not None:
            ctx.tag[links(stylesheets, path=self.original.pathToFiles)]
        stylesheets = getattr(self.original.resource, 'stylesheets', None)
        if stylesheets is not None:
            ctx.tag[links(stylesheets)]
        return ctx.tag

    def render_content(self, ctx, data):
        return self.original.content
