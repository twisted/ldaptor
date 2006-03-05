from zope.interface import implements
from webut.skin import iskin
from ldaptor.apps.webui import login, search, edit, add, delete, mass_change_password, change_password, move, iwebui
from ldaptor.protocols.ldap import distinguishedname
from ldaptor.apps.webui.uriquote import uriUnquote
from ldaptor import interfaces
from ldaptor.apps.webui.i18n import _
from ldaptor.apps.webui import i18n

from nevow import rend, loaders, url, static, inevow
from formless import annotate, webform, iformless
import os

class LdaptorWebUIGadget2(rend.Page):
    implements(iskin.ISkinnable)

    title = _('Ldaptor Web Interface')

    addSlash = True

    def __init__(self, baseObject):
        super(LdaptorWebUIGadget2, self).__init__()
        self.baseObject = baseObject

    def child_(self, context):
        return inevow.IRequest(context).URLPath().child('search')

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

class LdaptorWebUIGadget(rend.Page):
    implements(iskin.ISkinnable)

    title = _('Ldaptor Web Interface')

    addSlash = True

    docFactory = loaders.xmlfile(
        'basedn.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, loggedIn, config):
        super(LdaptorWebUIGadget, self).__init__()
        self.loggedIn = loggedIn
        self.config = config

    def getBindingNames(self, ctx):
        return ['go']

    def bind_go(self, ctx):
        return annotate.MethodBinding(
            'go',
            annotate.Method(arguments=[
            annotate.Argument('ctx', annotate.Context()),
            annotate.Argument('baseDN', LDAPDN(
            label=_('Base DN'),
            description=_("The top-level LDAP DN you want"
                          " to browse, e.g. dc=example,dc=com"))),
            ],
                            label=_('Go')),
            action=_('Go'))

    def go(self, ctx, baseDN):
        u = url.URL.fromContext(ctx)
        u = u.child(str(baseDN))
        return u

    def render_form(self, context, data):
        return webform.renderForms()

    def locateChild(self, ctx, segments):
        ret = super(LdaptorWebUIGadget, self).locateChild(ctx, segments)
        if ret != rend.NotFound:
            return ret

        path = segments[0]
        unquoted=uriUnquote(path)
        try:
            dn = distinguishedname.DistinguishedName(stringValue=unquoted)
        except distinguishedname.InvalidRelativeDistinguishedName, e:
            # TODO There's no way to throw a FormException at this stage.
            u = url.URL.fromContext(ctx)

            # TODO protect against guard bug, see
            # http://divmod.org/users/roundup.twistd/nevow/issue74
            u = u.child('')

            # TODO freeform_post!configurableName!methodName
            u.add('basedn', path)
            return u, []

        r=LdaptorWebUIGadget2(baseObject=dn)
        ctx.remember(self.config, interfaces.ILDAPConfig)
        ctx.remember(dn, iwebui.ICurrentDN)
        return r, segments[1:]

    render_i18n = i18n.render()
