from twisted.python import components
from twisted.web import resource, util
from twisted.python import urlpath

class IRedirectAfterLogin(components.Interface):
    """The URLPath to which we will redirect after successful login.
    """

class FullURLRequest:
    def __init__(self, request):
        self.request = request

    def prePathURL(self):
        r = self.request
        prepath = r.prepath
        r.prepath = r.prepath + r.postpath
        rv = r.prePathURL()
        r.prepath = prepath
        return rv

class InfiniChild(resource.Resource):
    def __init__(self, r):
        resource.Resource.__init__(self)
        self.r = r

    def getChild(self, name, request):
        return self

    def render(self, request):
        request.getSession().setComponent(
            IRedirectAfterLogin,
            urlpath.URLPath.fromRequest(FullURLRequest(request))
            )
        return self.r.render(request)

class Here(resource.Resource):
    def render(self, request):
        existing = request.getSession().getComponent(IRedirectAfterLogin, None)
        if existing is not None:
            request.redirect(str(existing))
            request.getSession().setComponent(IRedirectAfterLogin, None)
            return "<html></html>"
        else:
            return util.redirectTo('.', request)

def callback(model):
    return Here()
