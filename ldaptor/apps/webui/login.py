from twisted.web.woven import page, guard
from twisted.web import microdom
from twisted.python import urlpath

class LoginPage(page.Page):
    isLeaf = True
    """This is the page that is shown to non-logged in users."""

    addSlash = 0
    template = '''<html>
    <head>
        <title>Login</title>
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
    <h1>Please Log In</h1>
    <div class="shell">
    <div class="loginform" view="loginform" />
    </div>

    </body>
</html>'''

    def __init__(self, formModel=None):
        page.Page.__init__(self)
        self.formModel = formModel

    def wvupdate_loginform(self, request, widget, model):
        root = request.getRootURL()
        if root is None:
            root=request.prePathURL()
        url = urlpath.URLPath.fromString(root)
        microdom.lmx(widget.node).form(
            action=str(url.sibling(guard.INIT_PERSPECTIVE)),
            model="form")

    def wmfactory_form(self, request):
        if self.formModel:
            return self.formModel
        else:
            return guard.newLoginSignature.method(None)
