from twisted.web import widgets
from twisted.internet import defer
from twisted.python import failure

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldaperrors, ldapsyntax
from ldaptor.protocols.ldap import fetchschema
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote

from cStringIO import StringIO

import template

class LDAPSearch_FetchByDN(ldapclient.LDAPSearch):
    def __init__(self, deferred, client, dn):
	ldapclient.LDAPSearch.__init__(self, deferred, client,
				       baseObject=dn,
				       scope=pureldap.LDAP_SCOPE_baseObject,
				       sizeLimit=1,
				       )
	self.dn=dn

	self.found=0
	self.dn=None
	self.attributes=None
	deferred.addCallbacks(callback=self._ok,
			      errback=lambda x: x)


    def _ok(self, dummy):
	if self.found==0:
	    raise ldaperrors.LDAPUnknownError(ldaperrors.other, "No such DN")
	elif self.found==1:
	    return self.attributes
	else:
	    raise ldaperrors.LDAPUnknownError(ldaperrors.other,
					      "DN matched multiple entries")

    def handle_entry(self, objectName, attributes):
	self.found=self.found+1
	self.dn=objectName
	self.attributes=attributes

multiLineAttributeTypes = {
    'description': 1,
    }
def isAttributeTypeMultiLine(attributeType):
    for name in attributeType.name:
	if multiLineAttributeTypes.has_key(name):
	    assert not attributeType.single_value
	    return multiLineAttributeTypes[name]
    return 0

class EditForm(widgets.Form):
    nonEditableAttributes = {
	'objectClass': 1,
	}

    def __init__(self, dn, attributes, attributeTypes, objectClasses):
	attr={}
	for k,vs in attributes:
	    k=str(k)
	    vs=map(str, vs)
	    assert not attr.has_key(k)
	    attr[k]=vs

        self.object = ldapsyntax.LDAPEntry(client=None,
                                           dn=dn,
                                           attributes=attr)

	self.attributeTypes=attributeTypes
	self.objectClasses=objectClasses

    def _get_attrtype(self, name):
	for a in self.attributeTypes:
	    if name in a.name:
		a.uiHint_multiline=isAttributeTypeMultiLine(a)
		return a
	print "attribute type %s not known"%name
	return None

    def _one_formfield(self, attr, values, result):
	if not self.nonEditableAttributes.get(attr):
	    attrtype = self._get_attrtype(attr)
	    if attrtype.uiHint_multiline:
		if attrtype.single_value:
		    assert len(values)==1
                    for val in values:
                        result.append(('text', attr, 'edit_'+attr, val, attrtype.desc or ''))
                        result.append(('hidden', '', 'old_'+attr, val))
		else:
		    assert len(values)==1 # TODO handle multivalued multiline attributetypes
                    for val in values:
                        result.append(('text', attr, 'edit_'+attr, val, attrtype.desc or ''))
                        result.append(('hidden', '', 'old_'+attr, val))
	    else:
		if attrtype.single_value:
		    assert len(values)==1
                    for val in values:
                        result.append(('string', attr, 'edit_'+attr, val, attrtype.desc or ''))
                        result.append(('hidden', '', 'old_'+attr, val))
		else:
		    # TODO maybe use a string field+button to add entries,
		    # multiselection list+button to remove entries?
		    values=map(str, values)
		    result.append(('text', attr, 'edit_'+attr, "\n".join(values), attrtype.desc or ''))
		    result.append(('hidden', '', 'old_'+attr, "\n".join(values)))

    def getFormFields(self, request, kws={}):
	r=[]
	assert self.object

	process = {}
	for k in self.object.keys():
	    process[k.upper()]=k

	# TODO sort objectclasses somehow?
	objectClasses = list(self.object[process["OBJECTCLASS"]])
	objectClassesSeen = {}
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
		found_one=0
		real_attr = self._get_attrtype(str(attr_alias))
		for attr in real_attr.name:
		    if process.has_key(attr.upper()):
			found_one=1
			if process[attr.upper()]!=None:
			    self._one_formfield(attr,
						self.object[process[attr.upper()]],
						result=r)
			    for name in real_attr.name:
				process[name.upper()]=None

		if not found_one:
		    raise "Object doesn't have required attribute %s: %s"%(attr, self.object)

	    for attr_alias in objclass.may:
		found_one=0
		real_attr = self._get_attrtype(str(attr_alias))
		for attr in real_attr.name:
		    if process.has_key(attr.upper()):
			found_one=1
			if process[attr.upper()]!=None:
			    self._one_formfield(attr,
						self.object[process[attr.upper()]],
						result=r)

		if not found_one:
		    # a MAY attributetype not currently present in
		    # object, but user is of course free to add it.
		    attr=str(real_attr.name[0])
		    self._one_formfield(attr,
					('',),
					result=r)

		for name in real_attr.name:
		    process[name.upper()]=None

	assert [v==None for k,v in process.items()], "All attributes must be in objectClasses MUST or MAY: %s"%process
	return r

    def _textarea_to_list(self, t):
	return filter(lambda x: x, [x.strip() for x in t.split("\n")])

    def _prune_changes(self, old, new):
	"""Prune non-changes when old and new state is known."""
	o={}
	n={}
	for x in old:
	    n[x]=n.get(x, 0)+1
	for x in new:
	    o[x]=o.get(x, 0)+1

	for k in o.keys():
	    while o[k]>0:
		try:
		    old.remove(k)
		except ValueError:
		    break
		o[k]-=1

	for k in n.keys():
	    while n[k]>0:
		try:
		    new.remove(k)
		except ValueError:
		    break
		n[k]-=1

	return old, new

    def _output_status_and_form(self, request, kw, *status):
	io=StringIO()
	self.format(self.getFormFields(request, kw), io.write, request)
	return list(status)+["<P>", io.getvalue()]

    def process(self, write, request, submit, **kw):
	user = request.getSession().LdaptorPerspective.getPerspectiveName()
	client = request.getSession().LdaptorIdentity.getLDAPClient()

	if not client:
	    return self._output_status_and_form(
		request, kw,
		"<P>Edit failed: connection lost.")

	changes = []
	for k,v in kw.items():
	    if k[:len("edit_")]=="edit_":
		old=kw["old_"+k[len("edit_"):]]

		attrtype = self._get_attrtype(k[len("edit_"):])
		assert attrtype

		if attrtype.single_value or attrtype.uiHint_multiline:
		    v=[v]
		    old=[old]
		else:
		    v=self._textarea_to_list(v)
		    old=self._textarea_to_list(old)

		old, v = self._prune_changes(old, v)

		if old or v:
		    attr=k[len("edit_"):]
		    changes.append((attr, old, v))
		    #TODO
	if not changes:
            changes_desc=" no changes!"
	    defe=""
	else:
            self.object.client=client
            changes_desc=""
            for attr,old,new in changes:
                if new:
                    if self.object.has_key(attr):
                        self.object[attr].update(new)
                    else:
                        self.object[attr]=new
                if old:
                    for x in old:
                        if x=='':
                            continue
                        try:
                            self.object[attr].remove(x)
                        except ldapsyntax.CannotRemoveRDNError, e:
                            changes_desc=changes_desc+"<br>changing %s: cannot remove old value %s: %s"%(repr(attr), x, e)
                            old.remove(x)
                if old:
                    changes_desc=changes_desc+"<br>changing %s: remove %s"%(repr(attr), old)
                if new:
                    changes_desc=changes_desc+"<br>changing %s: add %s"%(repr(attr), new)

            defe=self.object.commit()
            defe.addCallbacks(
                callback=lambda dummy: "<p>Success.",
                errback=(lambda fail:
                         "<p><strong>Failed</strong>: %s" \
                         %fail.getErrorMessage()))

	return self._output_status_and_form(
	    request, kw,
	    "<P>Submitting edit as user %s.."%user,
            changes_desc,
	    defe)

class CreateEditForm:
    def __init__(self, defe, dn, request,
		 attributeTypes, objectClasses):
	self.deferred=defe
	self.dn=dn
	self.request=request
	self.attributeTypes=attributeTypes
	self.objectClasses=objectClasses

    def __call__(self, attributes):
	self.deferred.callback(
	    EditForm(self.dn, attributes,
		     self.attributeTypes,
		     self.objectClasses).display(self.request))
	return attributes

class CreateError:
    def __init__(self, defe, what, dn, request):
	self.deferred=defe
	self.what=what
	self.dn=dn
	self.request=request

    def __call__(self, fail):
	self.request.args['incomplete']=['true']
	self.deferred.callback(["Trouble while fetching %s for %s: %s.\n<HR>"%(self.what, repr(self.dn), fail.getErrorMessage())])

class NeedDNError(widgets.Widget):
    def display(self, request):
	return ['No DN specified. You need to use the <a href="%s">search page</a>.'%request.sibLink("search")]

class EditPage(template.BasicPage):
    title = "Ldaptor Edit Page"
    isLeaf = 1

    def _header(self, request):
	l=[]
	l.append('<a href="%s">Search</a>'%request.sibLink("search"))
	l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))

	if request.postpath and request.postpath!=['']:
	    l.append('<a href="%s">delete</a>' \
		     % request.sibLink("delete/" + uriUnquote(request.postpath[0])))
	    l.append('<a href="%s">change password</a>' \
		     % request.sibLink("change_password/" + '/'.join(request.postpath)))

	return '[' + '|'.join(l) + ']'

    def getContent(self, request):
	if not request.postpath or request.postpath==['']:
	    return NeedDNError()
	else:
	    dn=uriUnquote(request.postpath[0])

	    d=defer.Deferred()

	    client = request.getSession().LdaptorIdentity.getLDAPClient()
	    if client:
                deferred = fetchschema.fetch(client, dn)
                deferred.addCallback(self._getContent_3,
                                     dn, request, client, d)
                deferred.addErrback(CreateError(d, 'schema', dn, request))
	    else:
		CreateError(d, 'session client', dn, request)(
		    failure.Failure(
		    ldaperrors.LDAPUnknownError(ldaperrors.other,
						"connection lost")))

	    return [self._header(request), d]

    def _getContent_3(self, x, dn, request, client, d):
	attributeTypes, objectClasses = x
	deferred=defer.Deferred()
	LDAPSearch_FetchByDN(deferred, client, dn)
	deferred.addCallbacks(
	    callback=CreateEditForm(d, dn, request,
				    attributeTypes, objectClasses),
	    errback=CreateError(d, 'attributes', dn, request))
