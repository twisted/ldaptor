from twisted.web import widgets, guard, static
import search, edit, add, delete, mass_change_password, change_password
import template


# TODO when twisted.web.static with this class gets released,
# use it from there.
from twisted.web import resource
from twisted.protocols import http

class IndexPage(template.BasicPage):
    title = "Ldaptor Web Interface"
    isLeaf = 1

    def __init__(self):
        template.BasicPage.__init__(self)

    def getContent(self, request):
        return [static.redirectTo(request.childLink('search'), request)]

class LdaptorWebUIGadget(widgets.Gadget):
    def __init__(self, editService,
                 baseObject,
                 ldaphost,
                 ldapport):
        widgets.Gadget.__init__(self)

        siblings = {
            'search':
            search.SearchPage(baseObject=baseObject,
                              ldaphost=ldaphost,
                              ldapport=ldapport),

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
            baseObject=baseObject,
            ldaphost=ldaphost,
            ldapport=ldapport),
            editService,
            sessionPerspective="LdaptorPerspective",
            sessionIdentity="LdaptorIdentity"),

            'change_password':
            guard.ResourceGuard(change_password.PasswordChangePage(),
                                editService,
                                sessionPerspective="LdaptorPerspective",
                                sessionIdentity="LdaptorIdentity"),

            }

        self.putWidget('', IndexPage())
        for k,v in siblings.items():
            self.putWidget(k, v)
