from twisted.web import widgets, guard
import search, edit, add, delete, mass_password_change
import template


# TODO when twisted.web.static with this class gets released,
# use it from there.
from twisted.web import resource
from twisted.protocols import http
class Redirect(resource.Resource):
    def __init__(self, url):
        self.url = url

    def render(self, request):
        request.setHeader("location", self.url)
        request.setResponseCode(http.TEMPORARY_REDIRECT)
        return """
<html>
    <head>
        <meta http-equiv=\"refresh\" content=\"0;URL=%(url)s\">
    </head>
    <body bgcolor=\"#FFFFFF\" text=\"#000000\">
    <!- The user\'s browser must be incredibly feeble if they have to click...-->
        Click <a href=\"%(url)s\">here</a>.
    </body>
</html>
""" % {'url': self.url}

class IndexPage(template.BasicPage):
    title = "Ldaptor Web Interface"
    isLeaf = 1

    def __init__(self):
        template.BasicPage.__init__(self)

    def getContent(self, request):
        return [Redirect(request.childLink('search')).render(request)]

class LdaptorWebUIGadget(widgets.Gadget):
    def __init__(self, editService,
                 baseObject,
                 ldaphost,
                 ldapport):
        widgets.Gadget.__init__(self)

        siblings = {
            'search': search.SearchPage(baseObject=baseObject,
                                        ldaphost=ldaphost,
                                        ldapport=ldapport),
            'edit': guard.ResourceGuard(edit.EditPage(),
                                        editService,
                                        sessionPerspective="LdaptorPerspective",
                                        sessionIdentity="LdaptorIdentity"),
            'add': guard.ResourceGuard(add.AddPage(baseObject=baseObject),
                                       editService,
                                       sessionPerspective="LdaptorPerspective",
                                       sessionIdentity="LdaptorIdentity"),
            'delete': guard.ResourceGuard(delete.DeletePage(),
                                          editService,
                                          sessionPerspective="LdaptorPerspective",
                                          sessionIdentity="LdaptorIdentity"),
            'mass_password_change':
            guard.ResourceGuard(
            mass_password_change.MassPasswordChangePage(
            baseObject=baseObject,
            ldaphost=ldaphost,
            ldapport=ldapport),
            editService,
            sessionPerspective="LdaptorPerspective",
            sessionIdentity="LdaptorIdentity"),
            }

        self.putWidget('', IndexPage())
        for k,v in siblings.items():
            self.putWidget(k, v)
