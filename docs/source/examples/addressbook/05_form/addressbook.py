import os
from zope.interface import Interface, implements
from twisted.internet import reactor, defer
from twisted.cred import portal, checkers
from nevow import rend, appserver, inevow, \
     stan, guard, loaders, flat
from formless import annotate, webform

from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector, \
     distinguishedname
from ldaptor import ldapfilter
from ldaptor.protocols import pureldap

class ILDAPConfig(Interface):
    """Addressbook configuration retrieval."""

    def getBaseDN(self):
        """Get the LDAP base DN, as a DistinguishedName."""

    def getServiceLocationOverrides(self):
        """
        Get the LDAP service location overrides, as a mapping of
        DistinguishedName to (host, port) tuples.
        """

class LDAPConfig(object):
    implements(ILDAPConfig)

    def __init__(self,
                 baseDN,
                 serviceLocationOverrides=None):
        self.baseDN = distinguishedname.DistinguishedName(baseDN)
        self.serviceLocationOverrides = {}
        if serviceLocationOverrides is not None:
            for k,v in serviceLocationOverrides.items():
                dn = distinguishedname.DistinguishedName(k)
                self.serviceLocationOverrides[dn]=v

    def getBaseDN(self):
        return self.baseDN

    def getServiceLocationOverrides(self):
        return self.serviceLocationOverrides

class LDAPSearchFilter(annotate.String):
    def coerce(self, *a, **kw):
        val = super(LDAPSearchFilter, self).coerce(*a, **kw)
        try:
            f = ldapfilter.parseFilter(val)
        except ldapfilter.InvalidLDAPFilter, e:
            raise annotate.InputError, \
                  "%r is not a valid LDAP search filter: %s" % (val, e)
        return f

class IAddressBookSearch(annotate.TypedInterface):
    search = LDAPSearchFilter(label="Search filter")

class CurrentSearch(object):
    implements(IAddressBookSearch, inevow.IContainer)
    search = None

    def child(self, context, name):
        if name == 'searchFilter':
            return self.search
        if name != 'results':
            return None
        config = context.locate(ILDAPConfig)

        c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        d=c.connectAnonymously(config.getBaseDN(),
                               config.getServiceLocationOverrides())

        def _search(proto, base, searchFilter):
            baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=base)
            d=baseEntry.search(filterObject=searchFilter)
            return d

        d.addCallback(_search, config.getBaseDN(), self.search)
        return d

def LDAPFilterSerializer(original, context):
    return original.asText()

# TODO need to make this pretty some day.
for c in [
    pureldap.LDAPFilter_and,
    pureldap.LDAPFilter_or,
    pureldap.LDAPFilter_not,
    pureldap.LDAPFilter_substrings,
    pureldap.LDAPFilter_equalityMatch,
    pureldap.LDAPFilter_greaterOrEqual,
    pureldap.LDAPFilter_lessOrEqual,
    pureldap.LDAPFilter_approxMatch,
    pureldap.LDAPFilter_present,
    pureldap.LDAPFilter_extensibleMatch,
    ]:
    nevow.flat.registerFlattener(LDAPFilterSerializer, c)

class AddressBookResource(rend.Page):
    addSlash = True

    docFactory = loaders.xmlfile(
        'searchform.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def configurable_(self, context):
        request = context.locate(inevow.IRequest)
        i = request.session.getComponent(IAddressBookSearch)
        if i is None:
            i = CurrentSearch()
            request.session.setComponent(IAddressBookSearch, i)
        return i

    def data_search(self, context, data):
        d = defer.maybeDeferred(self.locateConfigurable, context, '')
        def cb(configurable):
            return configurable.original
        d.addCallback(cb)
        return d

    def child_form_css(self, request):
        return webform.defaultCSS

    def render_input(self, context, data):
        return webform.renderForms()

    def render_haveSearch(self, context, data):
        r=context.tag.allPatterns(str(data.search is not None))
        return context.tag.clear()[r]

    def render_searchFilter(self, context, data):
        return data.asText()

class AddressBookRealm:
    implements(portal.IRealm)

    def __init__(self, resource):
        self.resource = resource

    def requestAvatar(self, avatarId, mind, *interfaces):
        if inevow.IResource not in interfaces:
            raise NotImplementedError, "no interface"
        return (inevow.IResource,
                self.resource,
                lambda: None)

def getSite(config):
    form = AddressBookResource()
    form.remember(config, ILDAPConfig)
    realm = AddressBookRealm(form)
    site = appserver.NevowSite(
        guard.SessionWrapper(
        portal.Portal(realm, [checkers.AllowAnonymousAccess()])))
    return site
