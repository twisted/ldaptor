import os
from nevow import rend, loaders, guard, inevow, url

def getActionURL(current, history):
    action = current
    if len(history) == 1:
        action = action.here()
    else:
        for element in history[1:]:
            action = action.parent()

    action = action.child(guard.LOGIN_AVATAR)
    for element in history:
        action = action.child(element)
    return action

class LoginPage(rend.Page):
    """The resource that is returned when you are not logged in"""

    docFactory = loaders.xmlfile(
        'login.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, history):
        self.history = history
        super(LoginPage, self).__init__()

    def locateChild(self, request, segments):
        return LoginPage(self.history + list(segments)), []

    def render_form(self, context, data):
        request = context.locate(inevow.IRequest)
        current = url.URL.fromRequest(request)
        action = getActionURL(current, self.history)
        context.fillSlots('action-url', str(action))
        return context.tag
