from twisted.internet import reactor
from twisted.internet import defer
from twisted.web.util import Redirect
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor import generate_password
from ldaptor.apps.webui.uriquote import uriUnquote

import os
from nevow import rend, inevow, loaders, url, tags
from formless import annotate, webform, iformless

class IPasswordChange(annotate.TypedInterface):
    def setPassword(self,
                    context=annotate.Context(),
                    newPassword=annotate.Password(required=True)):
        pass
    setPassword = annotate.autocallable(setPassword)

    def generateRandom(self,
                       context=annotate.Context()):
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

    def data_css(self, context, data):
        request = context.locate(inevow.IRequest)
        u = (url.URL.fromRequest(request).clear().parent().parent().parent()
             .child('form.css'))
        return [ u ]

    def render_css_item(self, context, data):
        context.fillSlots('url', data)
        return context.tag

    def _prettifyExceptions(self, reason, prefix='', errorTypes=None):
        if errorTypes is not None:
            reason.trap(*errorTypes)
        return (prefix + reason.getErrorMessage())

    def _setPassword(self, context, password):
        entry = context.locate(inevow.ISession).getLoggedInRoot().loggedIn
        user = entry.dn
        client = entry.client

	e=ldapsyntax.LDAPEntry(client=client,
                               dn=self.dn)
        d=defer.maybeDeferred(e.setPassword, newPasswd=password)
        return d

    def setPassword(self, context, newPassword):
        d = self._setPassword(context, newPassword)
        d.addCallback(lambda dummy: 'Password set.')
        d.addErrback(self._prettifyExceptions,
                     prefix="Failed: ")
        return d

    def generateRandom(self, context):
        d=generate_password.generate(reactor)
        def _first(passwords):
            assert len(passwords)==1
            return passwords[0]
        d.addCallback(_first)

        def _status(newPassword, context):
            d = self._setPassword(context, newPassword)
            d.addCallback(lambda dummy: 'Password set to %s' % newPassword)
            return d
        d.addCallback(_status, context)
        d.addErrback(self._prettifyExceptions,
                     prefix="Failed: ")
        return d

    def data_status(self, context, data):
        try:
            return context.locate(inevow.IStatusMessage)
        except KeyError:
            return ''

    def data_dn(self, context, data):
        return self.dn

    def render_form(self, context, data):
        return webform.renderForms()

    def render_passthrough(self, context, data):
        return context.tag.clear()[data]

    def data_header(self, context, data):
        request = context.locate(inevow.IRequest)
        u=url.URL.fromRequest(request)
        u=u.parent().parent()
        l=[]
	l.append(tags.a(href=u.sibling("search"))["Search"])
	l.append(tags.a(href=u.sibling("add"))["add new entry"])
        l.append(tags.a(href=u.sibling("edit").child(str(self.dn)))["edit"])
        l.append(tags.a(href=u.sibling("delete").child(str(self.dn)))["delete"])
	return l

class GetDN(rend.Page):
    def renderHTTP(self, request):
        entry = request.getSession().getLoggedInRoot().loggedIn
        u = url.URL.fromRequest(request)
        request.redirect(u.child(str(entry.dn)))
        return ''

    def locateChild(self, request, segments):
        ret = super(GetDN, self).locateChild(request, segments)
        if ret != rend.NotFound:
            return ret

        path = segments[0]
        unquoted=uriUnquote(path)
        try:
            dn = distinguishedname.DistinguishedName(stringValue=unquoted)
        except distinguishedname.InvalidRelativeDistinguishedName, e:
            # TODO There's no way to throw a FormException at this stage.
            u = url.URL.fromRequest(request)
            # TODO freeform_post!configurableName!methodName
            u.add('dn', path)
            return Redirect(str(u)), []
        r=ConfirmChange(dn=dn)
        return r, segments[1:]

def getResource():
    return GetDN()
