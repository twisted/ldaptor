from twisted.web import widgets, guard, static
import search, edit, add, delete, mass_change_password, change_password, move
import template
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote

# TODO when twisted.web.static with this class gets released,
# use it from there.
from twisted.web import resource
from twisted.protocols import http


class LdaptorWebUIGadget2(widgets.Gadget):
    def __init__(self, editService,
                 baseObject,
                 serviceLocationOverride,
                 searchFields=(),
                 ):
        widgets.Gadget.__init__(self)

        siblings = {
            'search':
            search.SearchPage(baseObject=baseObject,
                              serviceLocationOverride=serviceLocationOverride,
                              searchFields=searchFields),

            'edit':
            guard.ResourceGuard(edit.EditPage(),
                                editService,
                                sessionPerspective="LdaptorPerspective",
                                sessionIdentity="LdaptorIdentity"),
            
            'add':
            guard.ResourceGuard(add.AddPage(baseObject=baseObject),
                                editService,
                                sessionPerspective="LdaptorPerspective",
                                sessionIdentity="LdaptorIdentity"),

            'delete':
            guard.ResourceGuard(delete.DeletePage(),
                                editService,
                                sessionPerspective="LdaptorPerspective",
                                sessionIdentity="LdaptorIdentity"),

            'mass_change_password':
            guard.ResourceGuard(
            mass_change_password.MassPasswordChangePage(
            baseObject=baseObject),
            editService,
            sessionPerspective="LdaptorPerspective",
            sessionIdentity="LdaptorIdentity"),

            'change_password':
            guard.ResourceGuard(change_password.PasswordChangePage(),
                                editService,
                                sessionPerspective="LdaptorPerspective",
                                sessionIdentity="LdaptorIdentity"),

            'move':
            guard.ResourceGuard(move.MovePage(
            baseObject=baseObject,
            serviceLocationOverride=serviceLocationOverride,
            searchFields=searchFields),
            editService,
            sessionPerspective="LdaptorPerspective",
            sessionIdentity="LdaptorIdentity"),

            }

        self.putWidget('', siblings['search'])
        for k,v in siblings.items():
            self.putWidget(k, v)

class AskBaseDNForm(widgets.Form):
    formFields = [
        ('string', 'Base DN', 'basedn', ''),
        ]

    def process(self, write, request, submit, basedn):
        quoted=uriQuote(basedn)
        return [static.redirectTo(request.childLink(quoted), request)]

class AskBaseDNPage(template.BasicPage):
    title = "Ldaptor Web Interface"
    isLeaf = 1

    def getContent(self, request):
        return AskBaseDNForm().display(request)

class LdaptorWebUIGadget(widgets.Gadget):
    def __init__(self, editService,
                 baseObject,
                 serviceLocationOverride,
                 searchFields=(),
                 ):
        self.editService=editService
        self.baseObject=baseObject
        self.serviceLocationOverride=serviceLocationOverride
        self.searchFields=searchFields
        widgets.Gadget.__init__(self)

    def getWidget(self, path, request):
        if not path:
            return AskBaseDNPage()
        else:
            unquoted=uriUnquote(path)
            return LdaptorWebUIGadget2(editService=self.editService,
                                       baseObject=unquoted,
                                       serviceLocationOverride=self.serviceLocationOverride,
                                       searchFields=self.searchFields)
