from twisted.web import widgets, static
from twisted.internet import defer, protocol
from twisted.python.failure import Failure
from ldaptor.protocols.ldap import ldapclient, ldapfilter
from ldaptor.protocols.ldap import distinguishedname, ldapconnector, ldapsyntax
from ldaptor.protocols import pureber, pureldap
from twisted.internet import reactor
from ldaptor.apps.webui.htmlify import htmlify_attributes
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote
import string

import template

import search
class LDAPSearchEntryMove(search.LDAPSearchEntry):
    def entryLink_001_edit(self, objectName, attributes):
	return []
    def entryLink_002_move(self, objectName, attributes):
	return []
    def entryLink_003_delete(self, objectName, attributes):
	return []
    def entryLink_004_change_password(self, objectName, attributes):
	return []
class DoSearchFactoryMove(search.DoSearchFactory):
    searchClass=LDAPSearchEntryMove
class MoveForm(search.SearchForm):
    searchFactory = DoSearchFactoryMove
    submitNames = ['Search', 'Put it here', 'Abort']

    def __init__(self, baseObject, serviceLocationOverride,
		 dn,
		 searchFields=(),
		 ):
	self.dn=dn
	search.SearchForm.__init__(self, baseObject,
				   serviceLocationOverride,
				   searchFields=searchFields)

    def _searchTrailer(self, filtText):
	return ''

    def process(self, write, request, submit, **kw):
	if submit == 'Abort':
	    return [static.redirectTo(
		request.sibLink('search'),
		request)]
	elif submit != 'Put it here':
	    return search.SearchForm.process(self, write, request, submit, **kw)
	base = distinguishedname.DistinguishedName(self.baseObject)
	dn = distinguishedname.DistinguishedName(self.dn)
	newDN = distinguishedname.DistinguishedName(
	    listOfRDNs=(dn.split()[0],)+base.split())

	user = request.getSession().LdaptorPerspective.getPerspectiveName()
	client = request.getSession().LdaptorIdentity.getLDAPClient()

	if not client:
	    return ["<P>Del failed: connection lost."]


	o = ldapsyntax.LDAPObject(client, dn)
	d = o.move(newDN)

	d.addCallback(lambda x: "<p>Success.")
	d.addErrback(lambda reason:
		     "<p><strong>Failed</strong>: %s."
		     % reason.getErrorMessage())

	return ['Moving %s to %s as user %s...' % (dn, newDN, user),
		d,
		'<p>Look at it with the <a href="../../%s">search page</a>.'
		% uriQuote(str(newDN))]

class NeedDNError(widgets.Widget):
    def display(self, request):
	return ['No DN specified. You need to use the <a href="%s">search page</a>.'%request.sibLink("search")]

class MovePage(template.BasicPage):
    title = "Ldaptor Move Page"
    isLeaf = 1

    def __init__(self, baseObject, serviceLocationOverride,
		 searchFields=(),
		 ):
	template.BasicPage.__init__(self)
	self.baseObject = baseObject
	self.serviceLocationOverride = serviceLocationOverride
	self.searchFields = searchFields

    def _header(self, request):
	return ''

    def _navilink(self, request, form):
	if (form.shouldProcess(request)
	    and request.args.get('submit')==['Put it here']):
	    done=1 # TODO shouldn't be "done" if it failed.. Oh well.
	else:
	    done=0


	dn=distinguishedname.DistinguishedName(stringValue=self.baseObject)
	fromDN=uriUnquote(request.postpath[0])

	r=[]
	while dn!=distinguishedname.DistinguishedName(stringValue=''):
	    firstPart=dn.split()[0]
	    if done:
		r.append('<a href="../../%s">%s</a>'
			 % (uriQuote(str(dn)), str(firstPart)))
	    else:
		r.append('<a href="../../%s/move/%s">%s</a>'
			 % (uriQuote(str(dn)), fromDN, str(firstPart)))
	    dn=dn.up()

	return ','.join(r)

    def getContent(self, request):
	if not request.postpath or request.postpath==['']:
	    return NeedDNError()
	else:
	    dn=uriUnquote(request.postpath[0])
	    form = MoveForm(baseObject=self.baseObject,
			    serviceLocationOverride
			    =self.serviceLocationOverride,
			    dn=dn,
			    searchFields=self.searchFields
			    )

	    return [self._navilink(request, form),
		    '<p>',
		    self._header(request)] \
		    + form.display(request)
