import os
from twisted.internet import reactor
from nevow import rend, appserver, inevow, compy, \
     stan, loaders
from formless import annotate, webform, iformless

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

class IAddressBookSearch(annotate.TypedInterface):
    def search(self,
               sn = annotate.String(label="Last name"),
               givenName = annotate.String(label="First name"),
               telephoneNumber = annotate.String(),
               description = annotate.String()):
        pass
    search = annotate.autocallable(search)

class CurrentSearch(object):
    __implements__ = IAddressBookSearch, inevow.IContainer
    data = {}

    def _getSearchFilter(self):
        filters = []
        for attr,value in self.data.items():
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

    def search(self, **kw):
        for k,v in kw.items():
            if v is None:
                del kw[k]
        self.data = kw
        return self

    def __nonzero__(self):
        return bool(self.data)

    def __iter__(self):
        if self.data is None:
            return
        for k,v in self.data.items():
            yield (k,v)

    def child(self, context, name):
        if name == 'searchFilter':
            return self._getSearchFilter()
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

        d.addCallback(_search, config.getBaseDN(), self._getSearchFilter())
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
    docFactory = loaders.xmlfile(
        'searchform.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def configurable_(self, context):
        try:
            i = context.locate(inevow.IHand)
        except KeyError:
            i = CurrentSearch()
        return i

    def data_search(self, context, data):
        configurable = self.locateConfigurable(context, '')
        cur = configurable.original
        return cur

    def child_form_css(self, request):
        return webform.defaultCSS

    def render_input(self, context, data):
        formDefaults = context.locate(iformless.IFormDefaults)
        methodDefaults = formDefaults.getAllDefaults('search')
        conf = self.configurable_(context)
        for k,v in conf:
            methodDefaults[k] = v
        return webform.renderForms()

    def render_haveSearch(self, context, data):
        r=context.allPatterns(str(bool(data)))
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

def getSite(config):
    form = AddressBookResource()
    form.remember(config, ILDAPConfig)
    site = appserver.NevowSite(form)
    return site
