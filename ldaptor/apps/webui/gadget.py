from twisted.web.util import Redirect, redirectTo
from ldaptor.apps.webui import login, search, edit, add, delete, mass_change_password, change_password, move
from ldaptor.protocols.ldap import distinguishedname
from ldaptor.apps.webui.uriquote import uriUnquote
from ldaptor import interfaces

from nevow import rend, loaders, url, static, inevow
from formless import annotate, webform, iformless
import os

class LdaptorWebUIGadget2(rend.Page):
    addSlash = True

    def __init__(self, baseObject):
        super(LdaptorWebUIGadget2, self).__init__()
        self.baseObject = baseObject

    def renderHTTP(self, context):
        request = inevow.IRequest(context)
        u = url.URL.fromRequest(request)
        request.redirect(u.child('search'))
        return ''

    def child_search(self, context):
        return search.getSearchPage()

    def child_edit(self, context):
        if not inevow.ISession(context).getLoggedInRoot().loggedIn:
            return login.LoginPage([str(self.baseObject), 'edit'])
        return edit.EditPage()

    def child_move(self, context):
        if not inevow.ISession(context).getLoggedInRoot().loggedIn:
            return login.LoginPage([str(self.baseObject), 'move'])
        return move.MovePage()

    def child_add(self, context):
        if not inevow.ISession(context).getLoggedInRoot().loggedIn:
            return login.LoginPage([str(self.baseObject), 'add'])
        return add.getResource(baseObject=self.baseObject,
                               request=inevow.IRequest(context))

    def child_delete(self, context):
        if not inevow.ISession(context).getLoggedInRoot().loggedIn:
            return login.LoginPage([str(self.baseObject), 'delete'])
        return delete.getResource()

    def child_mass_change_password(self, context):
        if not inevow.ISession(context).getLoggedInRoot().loggedIn:
            return login.LoginPage([str(self.baseObject), 'mass_change_password'])
        return mass_change_password.MassPasswordChangePage(
            baseObject=self.baseObject)

    def child_change_password(self, context):
        if not inevow.ISession(context).getLoggedInRoot().loggedIn:
            return login.LoginPage([str(self.baseObject), 'change_password'])
        return change_password.getResource()

class LDAPDN(annotate.String):
    def coerce(self, *a, **kw):
        val = super(LDAPDN, self).coerce(*a, **kw)
        try:
            dn = distinguishedname.DistinguishedName(stringValue=val)
        except distinguishedname.InvalidRelativeDistinguishedName, e:
            raise annotate.InputError, \
                  "%r is not a valid LDAP DN: %s" % (val, e)
        return dn

class IBaseDN(annotate.TypedInterface):
    def go(self,
           request=annotate.Request(),
           baseDN=LDAPDN(description="The top-level LDAP DN you want"
                         + " to browse, e.g. dc=example,dc=com")):
        pass
    go = annotate.autocallable(go)

class BaseDN(object):
    __implements__ = IBaseDN

    def go(self, request, baseDN):
        u = url.URL.fromRequest(request)
        u = u.child(str(baseDN))
        request.setComponent(iformless.IRedirectAfterPost, u)
        return 'Redirecting...'

class LdaptorWebUIGadget(rend.Page):
    addSlash = True

    docFactory = loaders.xmlfile(
        'basedn.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, loggedIn, config):
	super(LdaptorWebUIGadget, self).__init__()
        self.loggedIn = loggedIn
        self.config = config
        self.putChild('form.css', webform.defaultCSS)

        dirname = os.path.abspath(os.path.dirname(__file__))
        self.putChild('ldaptor.css', static.File(
            os.path.join(dirname, 'ldaptor.css')))

    def configurable_(self, context):
        return BaseDN()

    def render_form(self, context, data):
        return webform.renderForms()

    def locateChild(self, request, segments):
        ret = super(LdaptorWebUIGadget, self).locateChild(request, segments)
        if ret != rend.NotFound:
            return ret

        path = segments[0]
        unquoted=uriUnquote(path)
        try:
            dn = distinguishedname.DistinguishedName(stringValue=unquoted)
        except distinguishedname.InvalidRelativeDistinguishedName, e:
            # TODO There's no way to throw a FormException at this stage.
            u = url.URL.fromRequest(request)

            # TODO protect against guard bug, see
            # http://divmod.org/users/roundup.twistd/nevow/issue74
            u = u.child('')

            # TODO freeform_post!configurableName!methodName
            u.add('basedn', path)
            return Redirect(str(u)), []

        r=LdaptorWebUIGadget2(baseObject=dn)
        cfg = self.config.copy(baseDN=dn)
        r.remember(cfg, interfaces.ILDAPConfig)
        return r, segments[1:]
