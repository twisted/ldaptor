from twisted.internet import reactor
from twisted.internet import defer
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor import generate_password
from ldaptor.apps.webui.uriquote import uriUnquote

import os
from nevow import rend, inevow, loaders, url, tags
from formless import annotate, webform, iformless

class IPasswordChange(annotate.TypedInterface):
    def setPassword(self,
                    ctx=annotate.Context(),
                    newPassword=annotate.Password(required=True)):
        pass
    setPassword = annotate.autocallable(setPassword)

    def generateRandom(self,
                       ctx=annotate.Context()):
        pass
    generateRandom = annotate.autocallable(generateRandom)

class ConfirmChange(rend.Page):
    __implements__ = rend.Page.__implements__, IPasswordChange
    addSlash = True

    docFactory = loaders.xmlfile(
        'change_password.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, dn):
        super(ConfirmChange, self).__init__()
        self.dn = dn

    def data_css(self, ctx, data):
        request = ctx.locate(inevow.IRequest)
        u = (url.URL.fromRequest(request).clear().parent().parent().parent()
             .child('form.css'))
        return [ u ]

    def render_css_item(self, ctx, data):
        ctx.fillSlots('url', data)
        return ctx.tag

    def _prettifyExceptions(self, reason, prefix='', errorTypes=None):
        if errorTypes is not None:
            reason.trap(*errorTypes)
        return (prefix + reason.getErrorMessage())

    def _setPassword(self, ctx, password):
        entry = ctx.locate(inevow.ISession).getLoggedInRoot().loggedIn
        user = entry.dn
        client = entry.client

	e=ldapsyntax.LDAPEntry(client=client,
                               dn=self.dn)
        d=defer.maybeDeferred(e.setPassword, newPasswd=password)
        return d

    def setPassword(self, ctx, newPassword):
        d = self._setPassword(ctx, newPassword)
        d.addCallback(lambda dummy: 'Password set.')
        d.addErrback(self._prettifyExceptions,
                     prefix="Failed: ")
        return d

    def generateRandom(self, ctx):
        d=generate_password.generate(reactor)
        def _first(passwords):
            assert len(passwords)==1
            return passwords[0]
        d.addCallback(_first)

        def _status(newPassword, ctx):
            d = self._setPassword(ctx, newPassword)
            d.addCallback(lambda dummy: 'Password set to %s' % newPassword)
            return d
        d.addCallback(_status, ctx)
        d.addErrback(self._prettifyExceptions,
                     prefix="Failed: ")
        return d

    def data_status(self, ctx, data):
        try:
            return ctx.locate(inevow.IStatusMessage)
        except KeyError:
            return ''

    def data_dn(self, ctx, data):
        return self.dn

    def render_form(self, ctx, data):
        return webform.renderForms()

    def render_passthrough(self, ctx, data):
        return ctx.tag.clear()[data]

    def data_header(self, ctx, data):
        request = ctx.locate(inevow.IRequest)
        u=url.URL.fromRequest(request)
        u=u.parent().parent()
        l=[]
	l.append(tags.a(href=u.sibling("search"))["Search"])
	l.append(tags.a(href=u.sibling("add"))["add new entry"])
        l.append(tags.a(href=u.sibling("edit").child(str(self.dn)))["edit"])
        l.append(tags.a(href=u.sibling("delete").child(str(self.dn)))["delete"])
	return l

class GetDN(rend.Page):
    addSlash = True

    def child_(self, ctx):
        entry = inevow.ISession(ctx).getLoggedInRoot().loggedIn
        u = inevow.IRequest(ctx).URLPath()
        return u.child(str(entry.dn))

    def childFactory(self, ctx, name):
        unquoted=uriUnquote(name)
        try:
            dn = distinguishedname.DistinguishedName(stringValue=unquoted)
        except distinguishedname.InvalidRelativeDistinguishedName, e:
            # TODO There's no way to throw a FormException at this stage.
            return None
        r=ConfirmChange(dn=dn)
        return r

def getResource():
    return GetDN()
