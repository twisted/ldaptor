import os
from twisted.web import util
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.apps.webui.uriquote import uriUnquote
from nevow import rend, loaders, url, inevow

from ldaptor.apps.webui.search import IMove

class MovePage(rend.Page):
    addSlash = True
    docFactory = loaders.xmlfile(
        'move.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def render_url(self, context, data):
        request = context.locate(inevow.IRequest)
        u = url.URL.fromRequest(request)
        return context.tag(href=u.parent().child('search'))

    def getDynamicChild(self, name, request):
        dn = uriUnquote(name)
        session = request.getSession()
        userEntry = session.getLoggedInRoot().loggedIn

        move = session.getComponent(IMove)
        if move is None:
            move = []
            session.setComponent(IMove, move)

        e = ldapsyntax.LDAPEntryWithClient(dn=dn,
                                           client=userEntry.client)
        move.append(e)
        u = url.URL.fromRequest(request).sibling('search')
        return util.Redirect(str(u))
