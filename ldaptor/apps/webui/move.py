from twisted.web import widgets, static
from twisted.web.woven import simpleguard
from twisted.internet import defer, protocol
from twisted.python.failure import Failure
from ldaptor.protocols.ldap import ldapclient
from ldaptor.protocols.ldap import distinguishedname, ldapconnector, ldapsyntax
from ldaptor.protocols import pureber, pureldap
from ldaptor import ldapfilter
from twisted.internet import reactor
from ldaptor.apps.webui.htmlify import htmlify_attributes
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote
from twisted.python import reflect

import template

class OLD_LDAPSearchEntry(ldapclient.LDAPSearch):

    # I ended up separating the deferred that signifies when the
    # search is complete and whether it failed from the deferred that
    # generates web content. Maybe they should be combined some day.

    def __init__(self,
		 deferred,
		 contentDeferred,
		 client,
		 baseObject,
		 filter,
		 scope,
		 request):
	ldapclient.LDAPSearch.__init__(self, deferred, client,
				       baseObject=baseObject,
				       filter=filter,
				       sizeLimit=20,
				       scope=scope,
				       )
	self.baseObject=baseObject
	self.contentDeferred=contentDeferred
	self.request=request
	self.result=""
	self.count=0
	deferred.addCallbacks(self._ok, errback=self._fail)

    def _ok(self, dummy):
	self.contentDeferred.callback(
	    ["<p>%d entries matched."%self.count])
	return dummy

    def _fail(self, fail):
	self.contentDeferred.callback(["fail: %s"%fail.getErrorMessage()])

    def entryLink_001_edit(self, objectName, attributes):
	return ['<a href="%s">edit</a>\n'
		% self.request.sibLink('edit/'+uriQuote(objectName))]

    def entryLink_002_move(self, objectName, attributes):
	return ['<a href="%s">move</a>\n'
		% self.request.sibLink('move/'+uriQuote(objectName))]

    def entryLink_003_delete(self, objectName, attributes):
	return ['<a href="%s">delete</a>\n'
		% self.request.sibLink('delete/'+uriQuote(objectName))]

    def entryLink_004_change_password(self, objectName, attributes):
	return ['<a href="%s">change password</a>\n'
		% self.request.sibLink('change_password/'+uriQuote(objectName))]

    def _upLink(self, request, name):
	if request.postpath:
	    return (len(request.postpath)*"../") + "../" + name
	else:
	    return "../" + name

    def handle_entry(self, objectName, attributes):
	l=[]

	entryLinks = {}
	reflect.addMethodNamesToDict(self.__class__,
				     entryLinks, 'entryLink_')
	names = entryLinks.keys()
	names.sort()
	for name in names:
	    method = getattr(self, 'entryLink_'+name)
	    l.extend(method(objectName, attributes))

	entryLinks=''
	if l:
	    entryLinks='[' + '|'.join(l) + ']'

	r=[]
	dn=distinguishedname.DistinguishedName(stringValue=objectName)
	while dn!=self.baseObject \
	      and dn!=distinguishedname.DistinguishedName(stringValue=''):
	    firstPart=dn.split()[0]

	    me=self.request.path.split('/', 3)[2]
	    r.append('<a href="../%s">%s</a>'
		     % (self._upLink(self.request,
				     '/'.join([uriQuote(str(dn)), me]
					      + self.request.postpath)),
			str(firstPart)))
	    dn=dn.up()

	r.append('%s\n' % str(dn))

	result = (
	    '<p>'
	    + ','.join(r)
	    + entryLinks
	    + htmlify_attributes(attributes)
	    )

	d=defer.Deferred()
	self.contentDeferred.callback([result, d])
	self.contentDeferred=d
	self.count=self.count+1

class LDAPSearchEntryMove(OLD_LDAPSearchEntry):
    def entryLink_001_edit(self, objectName, attributes):
	return []
    def entryLink_002_move(self, objectName, attributes):
	return []
    def entryLink_003_delete(self, objectName, attributes):
	return []
    def entryLink_004_change_password(self, objectName, attributes):
	return []

class OLD_DoSearch(ldapclient.LDAPClient):
    factory = None

    def __init__(self):
	ldapclient.LDAPClient.__init__(self)

    def connectionMade(self):
	d=self.bind()
	d.addCallbacks(self._handle_bind_success,
		       self._handle_bind_fail)

    def _handle_bind_fail(self, fail):
	self.unbind()
	self.factory.deferred.errback(fail)
	raise fail

    def _handle_bind_success(self, x):
	matchedDN, serverSaslCreds = x
	self.factory.searchClass(self.factory.deferred,
				 self.factory.contentDeferred,
				 self,
				 baseObject=self.factory.baseObject,
				 filter=self.factory.ldapFilter,
				 scope=self.factory.scope,
				 request=self.factory.request)
	self.factory.deferred.addCallbacks(self._unbind, lambda x:x)

    def _unbind(self, dummy):
	self.unbind()
	return None # if we return self or x here, self is never deleted

class OLD_DoSearchFactory(protocol.ClientFactory):
    protocol=OLD_DoSearch
    searchClass=OLD_LDAPSearchEntry

    def __init__(self, deferred, contentDeferred, baseObject,
		 ldapFilter, scope, request):
	self.deferred=deferred
	self.contentDeferred=contentDeferred
	self.baseObject=baseObject
	self.ldapFilter=ldapFilter
	self.scope=scope
	self.request=request

    def clientConnectionFailed(self, connector, reason):
	self.deferred.errback(reason)

    def clientConnectionLost(self, connector, reason):
	if not self.deferred.called:
	    self.deferred.errback(reason)

class DoSearchFactoryMove(OLD_DoSearchFactory):
    searchClass=LDAPSearchEntryMove

class OLD_SearchForm(widgets.Form):
    searchFactory = OLD_DoSearchFactory
    formFields = [
	('string', 'Advanced', 'ldapfilter', ''),
	('radio', 'Search depth', 'scope',
	 (('wholeSubtree', 'whole subtree', 1),
	  ('singleLevel', 'single level', 0),
	  ('baseObject', 'baseobject', 0),
	  ),
	 ),
	]
    submitNames = ['Search']

    def __init__(self, baseObject, serviceLocationOverride,
		 searchFields=(),
		 ):
	self.baseObject = baseObject
	self.serviceLocationOverride = serviceLocationOverride
	self.searchFields = searchFields

    def getFormFields(self, request, kws=None):
	#TODO widgets.Form.getFormFields would be nicer
	# if it tried to get values from request; but that
	# parsing happens elsewhere, need to share code
	# and preferably results too.
	if kws is None:
	    kws={}
	r=[]

	for (displayName, filter) in self.searchFields:
	    inputType='string'
	    inputName='search_'+displayName
	    if kws.has_key(inputName):
		inputValue=kws[inputName]
	    else:
		inputValue=''
	    r.append((inputType, displayName, inputName, inputValue))

	for (inputType, displayName, inputName, inputValue) in self.formFields:
	    if inputType=='string':
		if kws.has_key(inputName):
		    inputValue=kws[inputName]
	    elif inputType=='radio':
		if kws.has_key(inputName):
		    checkedName=kws[inputName][0]
		    newInputValue=[]
		    for value, name, checked in inputValue:
			checked = (checkedName == value)
			newInputValue.append((value, name, checked))
		    inputValue = newInputValue
	    r.append((inputType, displayName, inputName, inputValue))

	return r

    def format(self, form, write, request):
	if self.shouldProcess(request):
	    widgets.Form.format(self, form, write, request)
	else:
	    widgets.Form.format(self, form, write, request)

	    deferred=defer.Deferred()
	    contentDeferred=defer.Deferred()

	    s = self.searchFactory(deferred,
				   contentDeferred,
				   baseObject=self.baseObject,
				   ldapFilter=pureldap.LDAPFilterMatchAll,
				   scope=pureldap.LDAP_SCOPE_baseObject,
				   request=request)

	    contentDeferred.addErrback(defer.logError)
	    deferred.addErrback(lambda reason, contentDeferred=contentDeferred:
				contentDeferred.callback(["fail: %s"
							  % reason.getErrorMessage()]))

	    c=ldapconnector.LDAPConnector(
		reactor, self.baseObject, s, overrides=self.serviceLocationOverride)
	    c.connect()

	    # Eww. But it'll do, t.w.widgets is deprecated anyway.
	    write(contentDeferred)

    def process(self, write, request, submit, **kw):
	from cStringIO import StringIO
	io=StringIO()
	self.format(self.getFormFields(request, kw), io.write, request)

	scope=pureldap.LDAP_SCOPE_wholeSubtree
	filt=[]
	for k,v in kw.items():
	    if k[:len("search_")]=="search_":
		k=k[len("search_"):]
		v=v.strip()
		if v=='':
		    continue

		filter = None
		for (displayName, searchFilter) in self.searchFields:
		    if k == displayName:
			filter = searchFilter
		# TODO handle not filter right (old form open in browser etc)
		assert filter
		# TODO escape ) in v
		filt.append(ldapfilter.parseFilter(filter % {'input': v}))
	    elif k=='ldapfilter' and v:
		filt.append(ldapfilter.parseFilter(v))
	    elif k=='scope' and len(v)==1:
		scope = getattr(pureldap, 'LDAP_SCOPE_'+v[0], scope)
	if filt:
	    if len(filt)==1:
		filt=filt[0]
	    else:
		filt=pureldap.LDAPFilter_and(filt)
	else:
	    filt=pureldap.LDAPFilterMatchAll
	deferred=defer.Deferred()
	contentDeferred=defer.Deferred()

	s = self.searchFactory(deferred,
			       contentDeferred,
			       baseObject=self.baseObject,
			       ldapFilter=filt,
			       scope=scope,
			       request=request)

	contentDeferred.addErrback(defer.logError)
	deferred.addErrback(lambda reason, contentDeferred=contentDeferred:
			    contentDeferred.callback(["fail: %s"
						      % reason.getErrorMessage()]))

	c=ldapconnector.LDAPConnector(reactor, self.baseObject, s,
				      overrides=self.serviceLocationOverride)
	c.connect()

	filtText=filt.asText()
	return [io.getvalue(),
		contentDeferred,
		'<P>Used filter %s' % filtText,
		self._searchTrailer(filtText),
		]

    def _searchTrailer(self, filtText):
	return '<P><a href="mass_change_password/%s">Mass change passwords</a>\n'%uriQuote(filtText)

class MoveForm(OLD_SearchForm):
    searchFactory = DoSearchFactoryMove
    submitNames = ['Search', 'Put it here', 'Abort']

    def __init__(self, baseObject, serviceLocationOverride,
		 dn,
		 searchFields=(),
		 ):
	self.dn=dn
	OLD_SearchForm.__init__(self, baseObject,
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
	    return OLD_SearchForm.process(self, write, request, submit, **kw)
	newDN = distinguishedname.DistinguishedName(
	    listOfRDNs=(self.dn.split()[0],)+self.baseObject.split())

        entry = request.getComponent(simpleguard.Authenticated).name
        user = entry.dn
        client = entry.client

	if not client:
	    return ["<P>Move failed: connection lost."]

	o = ldapsyntax.LDAPEntry(client, self.dn)
	d = o.move(newDN)

	d.addCallback(lambda x: "<p>Success.")
	d.addErrback(lambda reason:
		     "<p><strong>Failed</strong>: %s."
		     % reason.getErrorMessage())

	return ['Moving %s to %s as user %s...' % (self.dn, newDN, user),
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


	dn=self.baseObject
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
            dn=distinguishedname.DistinguishedName(stringValue=dn)
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
