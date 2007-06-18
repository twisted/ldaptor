from zope.interface import implements
import os
from nevow import rend, loaders, guard, url
from webut.skin import iskin
from ldaptor.apps.webui import i18n
from ldaptor.apps.webui.i18n import _

def getActionURL(current, history):
    action = current
    if len(history) == 1:
        action = action.here()
    else:
        for element in history[1:]:
            action = action.parentdir()

    action = action.child(guard.LOGIN_AVATAR)
    for element in history:
        action = action.child(element)
    return action

class LoginPage(rend.Page):
    """The resource that is returned when you are not logged in"""

    implements(iskin.ISkinnable)

    title = _('Login')

    docFactory = loaders.xmlfile(
        'login.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, history):
        self.history = history
        super(LoginPage, self).__init__()

    def locateChild(self, request, segments):
        return LoginPage(self.history + list(segments)), []

    def render_form(self, context, data):
        current = url.URL.fromContext(context)
        action = getActionURL(current, self.history)
        context.fillSlots('action-url', str(action))
        return context.tag

    render_i18n = i18n.render()
