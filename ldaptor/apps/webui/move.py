from zope.interface import implements
import os
from webut.skin import iskin
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.apps.webui.uriquote import uriUnquote
from nevow import rend, loaders, url, inevow
from ldaptor.apps.webui.i18n import _
from ldaptor.apps.webui import i18n

from ldaptor.apps.webui.search import IMove

class MovePage(rend.Page):
    implements(iskin.ISkinnable)

    title = _('Ldaptor Move Page')

    addSlash = True
    docFactory = loaders.xmlfile(
        'move.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def render_url(self, ctx, data):
        u = url.URL.fromContext(ctx)
        return ctx.tag(href=u.parentdir().child('search'))

    def childFactory(self, context, name):
        dn = uriUnquote(name)
        session = inevow.ISession(context)
        userEntry = session.getLoggedInRoot().loggedIn

        move = session.getComponent(IMove)
        if move is None:
            move = []
            session.setComponent(IMove, move)

        e = ldapsyntax.LDAPEntryWithClient(dn=dn,
                                           client=userEntry.client)
        move.append(e)
        u = url.URL.fromContext(context).sibling('search')
        return u

    render_i18n = i18n.render()
