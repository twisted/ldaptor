from twisted.web import microdom
from twisted.web.util import Redirect, redirectTo
from twisted.web.woven import simpleguard, page, form
from twisted.python import urlpath, formmethod
from ldaptor.apps.webui import util, login
import search, edit, add, delete, mass_change_password, change_password, move
from ldaptor.protocols.ldap import distinguishedname
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote
import urllib

class LdaptorWebUIGadget2(page.Page):
    def __init__(self,
                 baseObject,
		 serviceLocationOverride=None,
		 searchFields=(),
		 ):
        page.Page.__init__(self)
        self.baseObject = baseObject
        self.serviceLocationOverride = serviceLocationOverride
        self.searchFields = searchFields

    def render(self, request):
        if request.uri.split('?')[0][-1] != '/':
            return redirectTo(request.childLink('search'), request)
        else:
            return redirectTo(request.sibLink('search'), request)

    def wchild_search(self, request):
        return search.getSearchPage(
            baseObject=self.baseObject,
            serviceLocationOverride=self.serviceLocationOverride,
            searchFields=self.searchFields)

    def wchild_edit(self, request):
        a=request.getComponent(simpleguard.Authenticated)
        print 'wchild_edit', repr(a)
        if not request.getComponent(simpleguard.Authenticated):
            return util.InfiniChild(login.LoginPage())
        return edit.EditPage()

    def wchild_move(self, request):
        if not request.getComponent(simpleguard.Authenticated):
            return util.InfiniChild(login.LoginPage())
        return move.MovePage(
            baseObject=self.baseObject,
            serviceLocationOverride=self.serviceLocationOverride,
            searchFields=self.searchFields)

    def wchild_add(self, request):
        if not request.getComponent(simpleguard.Authenticated):
            return util.InfiniChild(login.LoginPage())
        return add.getResource(baseObject=self.baseObject,
                               request=request)

    def wchild_delete(self, request):
        if not request.getComponent(simpleguard.Authenticated):
            return util.InfiniChild(login.LoginPage())
        return delete.getResource()

    def wchild_mass_change_password(self, request):
        if not request.getComponent(simpleguard.Authenticated):
            return util.InfiniChild(login.LoginPage())
        return mass_change_password.MassPasswordChangePage(
            baseObject=self.baseObject)

    def wchild_change_password(self, request):
        if not request.getComponent(simpleguard.Authenticated):
            return util.InfiniChild(login.LoginPage())
        return change_password.getResource()

class LdaptorWebUIGadget(page.Page):
    appRoot = True

    template = '''<html>
    <head>
        <title>Ldaptor Web Interface</title>
        <style type="text/css">
.formDescription, .formError {
    /* fixme - inherit */
    font-size: smaller;
    font-family: sans-serif;
    margin-bottom: 1em;
}

.formDescription {
    color: green;
}

.formError {
    color: red;
}
</style>
    </head>
    <body>
    <h1>Base DN</h1>
    <div view="basednform" />

    </body>
</html>'''

    formSignature = formmethod.MethodSignature(
        formmethod.String("basedn", "",
                          "Base DN", "The top-level LDAP DN you want to browse, e.g. dc=example,dc=com"),
        formmethod.Submit("submit", allowNone=1),
        )

    def __init__(self,
		 serviceLocationOverride=None,
		 searchFields=(),
		 ):
	page.Page.__init__(self)
	self.serviceLocationOverride=serviceLocationOverride
	self.searchFields=searchFields

    def wvupdate_basednform(self, request, widget, model):
        root = request.getRootURL()
        if root is None:
            root=request.prePathURL()
        url = urlpath.URLPath.fromString(root)
        microdom.lmx(widget.node).form(
            action=str(url.child('process')),
            model="form")

    def wmfactory_form(self, request):
        return self.formSignature.method(None)

    def wchild_process(self, request):
        def process(basedn, submit=None):
            try:
                dn = distinguishedname.DistinguishedName(stringValue=basedn)
            except distinguishedname.InvalidRelativeDistinguishedName, e:
                raise formmethod.FormException, e
            return dn
        def callback(dn):
            return Redirect(str(dn))
        return form.FormProcessor(
            self.formSignature.method(process),
            callback=callback,
            )

    def getDynamicChild(self, path, request):
        unquoted=uriUnquote(path)
        try:
            dn = distinguishedname.DistinguishedName(stringValue=unquoted)
        except distinguishedname.InvalidRelativeDistinguishedName, e:
            # There's no way to throw a FormException at this stage,
            # so redirect to form submit. Ugly.
            url = urlpath.URLPath.fromRequest(request)
            url = url.sibling('process')
            url.query = urllib.urlencode([('basedn', path)])
            return Redirect(str(url))
        return LdaptorWebUIGadget2(baseObject=dn,
                                   serviceLocationOverride=self.serviceLocationOverride,
                                   searchFields=self.searchFields)
