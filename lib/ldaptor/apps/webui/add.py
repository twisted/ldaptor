from twisted.web import widgets, static
from twisted.internet import defer

from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldapclient, ldaperrors, ldapsyntax
from ldaptor.protocols.ldap import schema
from ldaptor import numberalloc
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote

from cStringIO import StringIO

import template

class DoAdd(ldapclient.LDAPAddEntry):
    def __init__(self, client, object, attributes, callback):
	ldapclient.LDAPAddEntry.__init__(self, client, object, attributes)
	self.callback=callback

    def handle_success(self):
	self.callback("<p>Success.")

    def handle_fail(self, fail):
	self.callback("<p><strong>Failed</strong>: %s."
		      %fail.getErrorMessage())

class AddForm(widgets.Form):
    def _nonUserEditableAttributeType_getFreeNumber(self, attributeType):
	o=ldapsyntax.LDAPObject(client=self.ldapClient,
				dn=self.baseObject)
	d=numberalloc.getFreeNumber(ldapObject=o,
                                    numberType=attributeType,
				    min=1000)
	d.addCallback(lambda x, a=attributeType: (a, [str(x)]))
	return d

    nonUserEditableAttributeType_uidNumber=_nonUserEditableAttributeType_getFreeNumber
    nonUserEditableAttributeType_gidNumber=_nonUserEditableAttributeType_getFreeNumber

    def __init__(self, baseObject, ldapClient,
		 chosenObjectClasses, attributeTypes, objectClasses):
	self.baseObject=baseObject
	self.ldapClient=ldapClient
	self.nonUserEditableAttributeType_objectClass=chosenObjectClasses
	self.attributeTypes=attributeTypes
	self.objectClasses=objectClasses

    def _get_attrtype(self, name):
	for a in self.attributeTypes:
	    if name in a.name:
		a.uiHint_multiline=0 #TODO
		return a
	print "attribute type %s not known"%name
	return None

    def _one_formfield(self, attr, result, must=0):
	attrtype = self._get_attrtype(attr)
	name=attr
	if must:
	    name=name+"*"
	if attrtype.uiHint_multiline:
	    if attrtype.single_value:
		result.append(('text', name, 'add_'+attr, "", attrtype.desc or ''))
	    else:
		result.append(('text', name, 'add_'+attr, "", attrtype.desc or ''))
	else:
	    if attrtype.single_value:
		result.append(('string', name, 'add_'+attr, "", attrtype.desc or ''))
	    else:
		# TODO maybe use a string field+button to add entries,
		# multiselection list+button to remove entries?
		result.append(('text', name, 'add_'+attr, "", attrtype.desc or ''))

    def getFormFields(self, request, kws={}):
	r=[]

	process = {}

	# TODO sort objectclasses somehow?
	objectClasses = request.postpath[0].split('+')
	objectClassesSeen = {}

	dn_attribute = None
	self.nonUserEditableAttributes = []
	while objectClasses:
	    objclassName = objectClasses.pop()

	    if objectClassesSeen.has_key(objclassName):
		continue
	    objectClassesSeen[objclassName]=1
	    objclass = None
	    for o in self.objectClasses:
		for name in o.name:
		    if objclassName.upper()==name.upper():
			objclass = o
	    assert objclass, "objectClass %s must have schema"%objclassName

	    objectClasses.extend(objclass.sup or [])


	    for attr_alias in objclass.must:
		if not dn_attribute and attr_alias != 'objectClass':
		    dn_attribute = attr_alias
		real_attr = self._get_attrtype(str(attr_alias))

		if hasattr(self, 'nonUserEditableAttributeType_'+real_attr.name[0]):
		    self.nonUserEditableAttributes.append(real_attr.name[0])
		else:
		    for attr in real_attr.name:
			if not process.has_key(attr.upper()):
			    process[attr.upper()]=0
			if not process[attr.upper()]:
			    self._one_formfield(attr, result=r, must=1)
			for name in real_attr.name:
			    process[name.upper()]=1

	    for attr_alias in objclass.may:
		real_attr = self._get_attrtype(str(attr_alias))

		if hasattr(self, 'nonUserEditableAttributeType_'+real_attr.name[0]):
		    self.nonUserEditableAttributes.append(real_attr.name[0])
		else:
		    for attr in real_attr.name:
			if not process.has_key(attr.upper()):
			    process[attr.upper()]=0
			if not process[attr.upper()]:
			    self._one_formfield(attr, result=r)
			for name in real_attr.name:
			    process[name.upper()]=1

	assert dn_attribute
	r.append(('hidden', '', 'dn', dn_attribute))
	assert [v==1 for k,v in process.items()], "TODO: %s"%process
	return r

    def _textarea_to_list(self, t):
	return filter(lambda x: x, [x.strip() for x in t.split("\n")])

    def _output_status_and_form(self, request, kw, *status):
	io=StringIO()
	self.format(self.getFormFields(request, kw), io.write, request)
	return list(status)+["<P>", io.getvalue()]

    def process(self, write, request, submit, **kw):
	assert kw['dn'], 'Must have dn set.'
	assert kw.has_key('add_'+kw['dn']), 'Must have attribute dn %s points to.' % kw['dn']
	assert kw['add_'+kw['dn']], 'Attribute %s must have value.' % 'add_'+kw['dn']
	dn=kw['dn']+'='+kw['add_'+kw['dn']]+','+self.baseObject

	#TODO verify
	changes = []
	for k,v in kw.items():
	    if hasattr(self, "nonUserEditableAttributeType_"+k):
		raise "Can't set attribute %s when adding." % k
	    elif k[:len("add_")]=="add_":
		attrtype = self._get_attrtype(k[len("add_"):])
		assert attrtype

		if attrtype.single_value or attrtype.uiHint_multiline:
		    v=[v]
		else:
		    v=self._textarea_to_list(v)

		if v and [1 for x in v if x]:
		    attr=k[len("add_"):]
		    changes.append(defer.succeed((attr, v)))
		    #TODO

	for attributeType in self.nonUserEditableAttributes:
	    thing=getattr(self, 'nonUserEditableAttributeType_'+attributeType)
	    if callable(thing):
		changes.append(thing(attributeType))
	    else:
		changes.append(defer.succeed((attributeType, thing)))

	dl=defer.DeferredList(changes, fireOnOneErrback=1)
	#dl.addErrback(lambda x: x[0]) # throw away index
	dl.addCallback(self._pruneSuccessFlags)
	dl.addCallback(self._process2, request, dn, kw)
	return [dl]

    def _pruneSuccessFlags(self, l):
	r=[]
	for succeeded,result in l:
	    assert succeeded
	    r.append(result)
	return r

    def _process2(self, changes, request, dn, kw):
	client = request.getSession().LdaptorIdentity.getLDAPClient()

	if not client:
	    return self._output_status_and_form(
		request, kw,
		"<P>Add failed: connection lost.")

	if not changes:
	    changes_desc=" no changes!" #TODO
	    defe=""
	else:
	    changes_desc=""
	    mod=[]
	    for attr,new in changes:
		if new:
		    mod.append((pureldap.LDAPAttributeDescription(attr),
				pureber.BERSet(
			map(pureldap.LDAPAttributeValue, new))))
		    changes_desc=changes_desc+"<br>adding %s: %s"%(repr(attr), ', '.join(map(repr, new)))
	    defe=defer.Deferred()
	    if not mod:
		defe.callback([""])
	    else:
		DoAdd(client, dn, mod, defe.callback)

	user = request.getSession().LdaptorPerspective.getPerspectiveName()
	return self._output_status_and_form(
	    request, kw,
	    "<P>Submitting add of %s as user %s.."%(dn, user),
	    changes_desc,
	    defe)

class AddError:
    def __init__(self, defe, request):
	self.deferred=defe
	self.request=request

    def __call__(self, resultCode=None, errorMessage=""):
	self.request.args['incomplete']=['true']
	if errorMessage:
	    errorMessage=": "+errorMessage
	if resultCode!=None:
	    errorMessage = str(resultCode)+errorMessage
	self.deferred.callback(["Got error%s.\n<HR>"%errorMessage])

class ChooseObjectClass(widgets.Form):
    def __init__(self, allowedObjectClasses):
	self.allowedObjectClasses = allowedObjectClasses

    def getFormFields(self, request):
	l=[]
	for oc in self.allowedObjectClasses:
	    l.append((oc, oc))
	return [('multimenu', 'Object types to create', 'objectClass', l)]

    def process(self, write, request, submit, **kw):
	return [static.redirectTo(
	    request.childLink('+'.join(kw['objectClass'])),
	    request)]

class AddPage(template.BasicPage):
    title = "Ldaptor Add Page"
    isLeaf = 1

    allowedObjectClasses = None

    def __init__(self, baseObject):
	template.BasicPage.__init__(self)
	self.baseObject = baseObject

    def _header(self, request):
	l=[]
	l.append('<a href="%s">Search</a>'%request.sibLink("search"))
	l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))

	if request.args.get('dn') \
	   and request.args.get('dn')[0]:
	    dnattr=request.args['dn'][0]
	    if request.args.get('add_'+dnattr):
		dn=dnattr+'='+request.args.get('add_'+dnattr)[0]+','+self.baseObject
		l.append('<a href="%s">edit</a>' \
			 % request.sibLink('edit/%s' % uriQuote(dn)))
		l.append('<a href="%s">delete</a>' \
			 % request.sibLink('delete/%s' % uriQuote(dn)))
		l.append('<a href="%s">change password</a>' \
			 % request.sibLink('change_password/%s' % uriQuote(dn)))

	return '[' + '|'.join(l) + ']'

    def getContent(self, request):
	d=defer.Deferred()

	if self.allowedObjectClasses == None:
	    client = request.getSession().LdaptorIdentity.getLDAPClient()
	    if client:
		deferred=defer.Deferred()
		schema.LDAPGet_subschemaSubentry(
		    deferred, client, self.baseObject)
		deferred.addCallbacks(
		    callback=self._getContent_have_subschemaSubentry,
		    callbackArgs=(request, client, d),
		    errback=AddError(d, request),
		    )
	    else:
		AddError(d, request)(errorMessage="connection lost")
	else:
	    self._getContent_real(request, d)

	return [self._header(request), d]

    def _getContent_have_subschemaSubentry(self, subschemaSubentry,
					   request, client, d):
	deferred=defer.Deferred()
	schema.LDAPGetSchema(
	    deferred,
	    client, subschemaSubentry,
	    )
	deferred.addCallbacks(
	    callback=self._getContent_have_objectClasses,
	    callbackArgs=(request, d),
	    errback=AddError(d, request),
	    )

    def _getContent_have_objectClasses(self, x, request, d):
	attributeTypes, objectClasses = x
	r = []
	for o in objectClasses:
	    r.append(o.name[0])
	self.allowedObjectClasses = r
	self._getContent_real(request, d)

    def _getContent_real(self, request, d):
	assert self.allowedObjectClasses != None
	assert self.allowedObjectClasses != []
	if not request.postpath or request.postpath==['']:
	    d.callback(ChooseObjectClass(self.allowedObjectClasses).display(request))
	else:
	    chosenObjectClasses = request.postpath[0].split('+')
	    for oc in chosenObjectClasses:
		if oc not in self.allowedObjectClasses:
		    d.callback(ChooseObjectClass(self.allowedObjectClasses).display(request))
		    return

	    client = request.getSession().LdaptorIdentity.getLDAPClient()
	    if client:
		deferred=defer.Deferred()
		schema.LDAPGet_subschemaSubentry(
		    deferred, client, self.baseObject)
		deferred.addCallbacks(
		    callback=self._getContent_2,
		    callbackArgs=(chosenObjectClasses, request, client, d),
		    errback=AddError(d, request),
		    )
	    else:
		AddError(d, request)(errorMessage="connection lost")

    def _getContent_2(self, subschemaSubentry, chosenObjectClasses, request, client, d):
	deferred=defer.Deferred()
	schema.LDAPGetSchema(
	    deferred, client, subschemaSubentry)
	deferred.addCallbacks(
	    callback=self._getContent_3,
	    callbackArgs=(chosenObjectClasses, request, client, d),
	    errback=AddError(d, request),
	    )

    def _getContent_3(self, x, chosenObjectClasses, request, client, d):
	attributeTypes, objectClasses = x
	d.callback(AddForm(baseObject=self.baseObject,
			   ldapClient=client,
			   chosenObjectClasses=chosenObjectClasses,
			   attributeTypes=attributeTypes,
			   objectClasses=objectClasses).display(request))
