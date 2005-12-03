from twisted.cred import portal, checkers, credentials
from nevow import guard, inevow
from ldaptor.config import LDAPConfig
from ldaptor.apps.webui import gadget
from ldaptor.checkers import LDAPBindingChecker

class TODOGetRidOfMeRealm:
    __implements__ = portal.IRealm,

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def requestAvatar(self, avatarId, mind, *interfaces):
        if inevow.IResource not in interfaces:
            raise NotImplementedError, "no interface"

        if avatarId is checkers.ANONYMOUS:
            resource = gadget.LdaptorWebUIGadget(None, *self.args, **self.kwargs)
            resource.realm = self
            return (inevow.IResource,
                    resource,
                    lambda: None)
        else:
            resource = gadget.LdaptorWebUIGadget(avatarId, *self.args, **self.kwargs)
            resource.realm = self
            return (inevow.IResource,
                    resource,
                    lambda: None)

def getResource(cfg=None):
    """Get a resource for the Ldaptor-webui app."""

    if cfg is None:
        cfg = LDAPConfig()

    checker = LDAPBindingChecker(cfg)
    realm = TODOGetRidOfMeRealm(config=cfg)
    porta = portal.Portal(realm)
    porta.registerChecker(checkers.AllowAnonymousAccess(), credentials.IAnonymous)
    porta.registerChecker(checker)

    mainResource = guard.SessionWrapper(porta)

    return mainResource
