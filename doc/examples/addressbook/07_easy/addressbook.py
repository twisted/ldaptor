import os
from twisted.internet import reactor
from twisted.cred import portal, checkers
from nevow import rend, appserver, formless, freeform, inevow, compy, \
     stan, guard

from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector, \
     distinguishedname
from ldaptor import ldapfilter
from ldaptor.protocols import pureldap

class ILDAPConfig(compy.Interface):
    """Addressbook configuration retrieval."""

    def getBaseDN(self):
        """Get the LDAP base DN, as a DistinguishedName."""

    def getServiceLocationOverrides(self):
        """
        Get the LDAP service location overrides, as a mapping of
        DistinguishedName to (host, port) tuples.
        """

class LDAPConfig(object):
    __implements__ = ILDAPConfig

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

class IAddressBookSearch(formless.TypedInterface):
    class Search(formless.TypedInterface):
        sn = formless.String()
        sn.allowNone = True
        sn.label = "Last name"

        givenName = formless.String()
        givenName.allowNone = True
        givenName.label = "First name"

        telephoneNumber = formless.String()
        telephoneNumber.allowNone = True

        description = formless.String()
        description.allowNone = True

class CurrentSearch(object):
    __implements__ = IAddressBookSearch, inevow.IContainer

    def _getSearchFilter(self):
        filters = []

        for attr in [x for x in dir(IAddressBookSearch.Search)
                     if not x.startswith('_')]:
            value = getattr(self, attr, None)
            if value is not None:
                f = ldapfilter.parseMaybeSubstring(attr, value)
                filters.append(f)

        if not filters:
            return None
            
        searchFilter = pureldap.LDAPFilter_and(
            [pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription('objectClass'),
            assertionValue=pureldap.LDAPAssertionValue('addressbookPerson'))]
            + filters)
        return searchFilter
    search = property(
        fget = _getSearchFilter,
        fset = None)

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
    compy.registerAdapter(LDAPFilterSerializer,
                          c,
                          inevow.ISerializable)

class AddressBookResource(rend.Page):
    docFactory = rend.htmlfile(
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
        configurable = self.locateConfigurable(context, '')
        cur = configurable.original
        return cur

    def child_freeform_css(self, request):
        from twisted.python import util
        from twisted.web import static
        from nevow import __file__ as nevow_file
        return static.File(util.sibpath(nevow_file, 'freeform-default.css'))

    def render_input(self, context, data):
        return freeform.renderForms()

    def render_haveSearch(self, context, data):
        r=context.allPatterns(str(data.search is not None))
        return context.tag.clear()[r]

    def render_searchFilter(self, context, data):
        return data.asText()

    def render_iterateMapping(self, context, data):
        headers = context.allPatterns('header')
        keyPattern = context.patternGenerator('key')
        valuePattern = context.patternGenerator('value')
        divider = context.patternGenerator('divider', default=stan.invisible)
        content = [(keyPattern(data=key),
                    valuePattern(data=value),
                    divider())
                   for key, value in data.items()]
        if not content:
            content = context.allPatterns('empty')
        else:
            # No divider after the last thing.
            content[-1] = content[-1][:-1]
        footers = context.allPatterns('footer')
    
        return context.tag.clear()[ headers, content, footers ]

class AddressBookRealm:
    __implements__ = portal.IRealm,

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
