from twisted.application import internet
from ldaptor.protocols.ldap import distinguishedname
from ldaptor.apps.webui import gadget
from ldaptor.checkers import LDAPBindingChecker
from twisted.web.woven import simpleguard
from ldaptor.apps.webui import util

def getResource(
    identityBaseDN,
    serviceLocationOverride={},
    searchFields=[]):
    gdgt = gadget.LdaptorWebUIGadget(
        serviceLocationOverride=serviceLocationOverride,
        searchFields=searchFields,
        )

    checker = LDAPBindingChecker(identityBaseDN, serviceLocationOverride)

    mainResource = simpleguard.guardResource(
        gdgt,
        [checker],
        callback=util.callback)

    return mainResource
