from twisted.internet import defer, protocol
from twisted.python import reflect, formmethod
from ldaptor.protocols.ldap import ldapclient, ldapsyntax
from ldaptor.protocols.ldap import distinguishedname, ldapconnector
from ldaptor.protocols import pureber, pureldap
from ldaptor import ldapfilter
from twisted.internet import reactor
from ldaptor.apps.webui.htmlify import htmlify_attributes
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote
from twisted.web.woven import page, view, form
from twisted.web.microdom import lmx
from ldaptor import weave

class EntryLinks:
    def __init__(self, objectName, request):
        self.objectName = objectName
        self.request = request

    def entryLink_001_edit(self, objectName):
	return ['<a href="%s">edit</a>\n'
		% self.request.sibLink('edit/'+uriQuote(objectName))]

    def entryLink_002_move(self, objectName):
	return ['<a href="%s">move</a>\n'
		% self.request.sibLink('move/'+uriQuote(objectName))]

    def entryLink_003_delete(self, objectName):
	return ['<a href="%s">delete</a>\n'
		% self.request.sibLink('delete/'+uriQuote(objectName))]

    def entryLink_004_change_password(self, objectName):
	return ['<a href="%s">change password</a>\n'
		% self.request.sibLink('change_password/'+uriQuote(objectName))]

    def __str__(self):
	l=[]

	entryLinks = {}
	reflect.addMethodNamesToDict(self.__class__,
				     entryLinks, 'entryLink_')
	names = entryLinks.keys()
	names.sort()
	for name in names:
	    method = getattr(self, 'entryLink_'+name)
	    l.extend(method(self.objectName))

	entryLinks=''
	if l:
	    entryLinks='[' + '|'.join(l) + ']'
        return entryLinks

def _upLink(request, name):
    if request.postpath:
        return (len(request.postpath)*"../") + "../" + name
    else:
        return "../" + name

def prettyLinkedDN(dn, baseObject, request):
    r=[]
    while (dn!=baseObject
           and dn!=distinguishedname.DistinguishedName(stringValue='')):
        firstPart=dn.split()[0]

        me=request.path.split('/', 3)[2]
        r.append('<a href="../%s">%s</a>'
                 % (_upLink(request,
                            '/'.join([uriQuote(str(dn)), me]
                                     + request.postpath)),
                    str(firstPart)))
        dn=dn.up()

    r.append('%s\n' % str(dn))
    return ','.join(r)

class Searcher:
    def __init__(self, **config):
        self.config = config

    def search(self, submit, searchfilter, scope, **kw):
        if not submit:
            return {}

	filt=[]
	for k,v in kw.items():
	    if k[:len("search_")]=="search_":
		k=k[len("search_"):]
		v=v.strip()
		if v=='':
		    continue

		filter = None
		for (displayName, searchFilter) in self.config['searchFields']:
		    if k == displayName:
			filter = searchFilter
		# TODO handle not filter right (old form open in browser etc)
		assert filter
		# TODO escape ) in v
		filt.append(ldapfilter.parseFilter(filter % {'input': v}))
        if searchfilter:
            filt.append(ldapfilter.parseFilter(searchfilter))

	if filt:
	    if len(filt)==1:
		query=filt[0]
	    else:
		query=pureldap.LDAPFilter_and(filt)
	else:
	    query=pureldap.LDAPFilterMatchAll

        c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        d=c.connectAnonymously(self.config['base'], self.config['serviceLocationOverrides'])

        def _search(proto, base, query):
            baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=base)
            d=baseEntry.search(filterObject=query,
                               scope=scope,
                               sizeLimit=20,
                               sizeLimitIsNonFatal=True)
            return d

        d.addCallback(_search, self.config['base'], query)
        d.addCallback(lambda results: {'query': query.asText(), 'results': results})
        return d

class SearchPage(page.Page):
    templateFile = 'search.xhtml'
    isLeaf = 1

    def wmfactory_title(self, request):
        return "Ldaptor Search Page"

    def __init__(self, formModel, baseObject, serviceLocationOverride, formSignature):
	page.Page.__init__(self)
        self.formModel = formModel
	self.baseObject = baseObject
	self.serviceLocationOverride = serviceLocationOverride
        self.formSignature = formSignature

    def wmfactory_header(self, request):
	return [
            '<a href="%s">add new entry</a>'%request.sibLink("add"),
            ]

    def wmfactory_form(self, request):
        return self.formModel

    def _navilink(self, request):
	dn=self.baseObject

	r=[]
	while dn!=distinguishedname.DistinguishedName(stringValue=''):
	    firstPart=dn.split()[0]
	    r.append('<a href="../%s">%s</a>' % (uriQuote(str(dn)), str(firstPart)))
	    dn=dn.up()

	return ','.join(r)

    def wmfactory_base(self, request):
        c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        d=c.connectAnonymously(self.baseObject, self.serviceLocationOverride)

        def _search(proto, base):
            baseEntry = ldapsyntax.LDAPEntry(client=proto,
                                             dn=base)
            d=baseEntry.search(scope=pureldap.LDAP_SCOPE_baseObject,
                               sizeLimit=1)
            return d
        d.addCallback(_search, self.baseObject)

        def _first(results):
            assert len(results)==1
            return results[0]
        d.addCallback(_first)

        return d

    def wvupdate_navilink(self, request, widget, model):
        node = lmx(widget.node)
        node.text(self._navilink(request), raw=1)

    def wvupdate_if(self, request, widget, model):
        if not model:
            while 1:
                c=widget.node.firstChild()
                if c is None:
                    break
                widget.node.removeChild(c)

    def wvupdate_ifNot(self, request, widget, model):
        return self.wvupdate_if(request, widget, not model)

    def wvupdate_searchform(self, request, widget, model):
        lmx(widget.node).form(model="formsignature")

    def wmfactory_formsignature(self, request):
        return self.formSignature.method(None)

    def wvupdate_linkedDN(self, request, widget, model):
        node = lmx(widget.node)
        e = prettyLinkedDN(model, self.baseObject, request)
        node.text(e, raw=1)

    def wvupdate_entryLinks(self, request, widget, model):
        node = lmx(widget.node)
        e = str(EntryLinks(model, request))
        node.text(e, raw=1)

    def wvupdate_listLen(self, request, widget, model):
        node = lmx(widget.node)
        if model is None:
            length = 0
        else:
            length = len(model)
        node.text('%d' % length)

    def wvfactory_ldapEntry(self, request, node, model):
        return weave.LDAPEntryWidget(model)

    def wvfactory_dictWidget(self, request, node, model):
        return weave.DictWidget(model)

    def wvfactory_separatedList(self, request, node, model):
        return weave.SeparatedList(model)

    def wmfactory_mass_change_password(self, request):
        form = self.getSubmodel(request, 'form')
        query = form.getSubmodel(request, 'query')
        filtText = query.original
        url = request.sibLink("mass_change_password/%s" % uriQuote(filtText))
        return url

# This has to be named Choice or
# twisted.web.woven.form.FormFillerWidget.createInput tries to access
# something other than self.input_choice
class Choice(formmethod.Choice):
    def coerce(self, inIdent):
        try:
            r=formmethod.Choice.coerce(self, inIdent)
        except formmethod.InputError, e:
            if str(e) != 'Invalid Choice: ': #TODO ugly
                raise
            r=formmethod.Choice.coerce(self, self.default[0])
        else:
            return r

def getSearchPage(baseObject,
                  serviceLocationOverride,
                  searchFields):
    sig = []
    for field, filter in searchFields:
        sig.append(formmethod.String(name='search_'+field, shortDesc=field))
    formSignature = formmethod.MethodSignature(
        *(sig
          + [ formmethod.String('searchfilter', allowNone=1, shortDesc="Advanced"),
              Choice('scope',
                       choices=[ ('wholeSubtree', pureldap.LDAP_SCOPE_wholeSubtree, 'whole subtree'),
                                 ('singleLevel', pureldap.LDAP_SCOPE_singleLevel, 'single level'),
                                 ('baseObject', pureldap.LDAP_SCOPE_baseObject, 'baseobject'),
                                 ],
                       default=['wholeSubtree'],
                       shortDesc='Search depth'),
              formmethod.Submit('submit', shortDesc='Search', allowNone=1),
              ]))
    class _P(form.FormProcessor):
        isLeaf=1
    return _P(formSignature.method(
        Searcher(base=baseObject,
                 searchFields=searchFields,
                 serviceLocationOverrides=serviceLocationOverride).search),
                              callback=lambda model: SearchPage(model, baseObject, serviceLocationOverride, formSignature))
