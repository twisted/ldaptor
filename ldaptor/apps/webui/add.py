from twisted.web import widgets
from twisted.web import microdom
from twisted.web.util import Redirect, DeferredResource
from twisted.web.woven import simpleguard, page, form
from twisted.python import urlpath, formmethod
from twisted.internet import defer

from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldapclient, ldapsyntax
from ldaptor.protocols.ldap import fetchschema
from ldaptor import numberalloc
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote

from cStringIO import StringIO

import template

def mapNameToObjectClass(objectClasses, name):
    name = name.upper()
    objclass = None
    for oc in objectClasses:
        for ocName in oc.name:
            if ocName.upper()==name:
                objclass = oc
    return objclass

def mapNameToAttributeType(attributeTypes, name):
    name = name.upper()
    attrtype = None
    for at in attributeTypes:
        for atName in at.name:
            if atName.upper()==name:
                attrtype = at
    return attrtype

class UnknownAttributeType(Exception):
    """LDAP Attribute type not known"""

    def __init__(self, name):
        Exception.__init__(self)
        self.name = name

    def __str__(self):
        return self.__doc__ + ': ' + repr(self.name)

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
    def _nonUserEditableAttributeType_getFreeNumber(self, attributeType, request):
        entry = request.getComponent(simpleguard.Authenticated).name
        client = entry.client
	o=ldapsyntax.LDAPEntry(client=client,
                               dn=self.baseObject)
	d=numberalloc.getFreeNumber(ldapObject=o,
                                    numberType=attributeType,
				    min=1000)
	d.addCallback(lambda x, a=attributeType: (a, [str(x)]))
	return d

    nonUserEditableAttributeType_uidNumber=_nonUserEditableAttributeType_getFreeNumber
    nonUserEditableAttributeType_gidNumber=_nonUserEditableAttributeType_getFreeNumber

    def __init__(self, baseObject,
		 chosenObjectClasses, attributeTypes, objectClasses):
	self.baseObject=baseObject
        self.chosenObjectClasses=chosenObjectClasses
	self.nonUserEditableAttributeType_objectClass=[oc.name[0] for oc in self.chosenObjectClasses]
	self.attributeTypes=attributeTypes
	self.objectClasses=objectClasses

    def _get_attrtype(self, name):
	for a in self.attributeTypes:
	    if name in a.name:
		a.uiHint_multiline=0 #TODO
		return a
        raise UnknownAttributeType, name

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
        objectClasses = list(self.chosenObjectClasses)
	objectClassesSeen = {}

	dn_attribute = None
	self.nonUserEditableAttributes = []
	while objectClasses:
            objectClass = objectClasses.pop()
	    objclassName = objectClass.name[0]

	    if objectClassesSeen.has_key(objclassName):
		continue
	    objectClassesSeen[objclassName]=1

            for ocName in objectClass.sup or []:
                objclass = mapNameToObjectClass(self.objectClasses, ocName)
                assert objclass, "objectClass %s must have schema"%objclassName
                objectClasses.append(objclass)

	    for attr_alias in objectClass.must:
		if not dn_attribute and attr_alias != 'objectClass':
                    # map alias to canonical name of attribute type
                    attrType = mapNameToAttributeType(self.attributeTypes, attr_alias)
                    assert attrType is not None
		    dn_attribute = attrType.name[0]
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

	    for attr_alias in objectClass.may:
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
	dn=kw['dn']+'='+kw['add_'+kw['dn']]+','+str(self.baseObject)

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
		changes.append(thing(attributeType, request))
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
        entry = request.getComponent(simpleguard.Authenticated).name
        client = entry.client

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

        entry = request.getComponent(simpleguard.Authenticated).name
        user = entry.dn
	return self._output_status_and_form(
	    request, kw,
	    "<P>Submitting add of %s as user %s.."%(dn, user),
	    changes_desc,
	    defe)

class ReallyAddPage(template.BasicPage):
    title = "Ldaptor Add Object"

    def __init__(self,
                 baseObject,
                 structuralObjectClass,
                 auxiliaryObjectClasses,
                 attributeTypes,
                 objectClasses):
	template.BasicPage.__init__(self)
	self.baseObject = baseObject
        self.structuralObjectClass = structuralObjectClass
        self.auxiliaryObjectClasses = auxiliaryObjectClasses
        self.attributeTypes = attributeTypes
        self.objectClasses = objectClasses

    def _header(self, request):
	l=[]
	l.append('<a href="%s">Search</a>' % request.URLPath().parent().sibling("search"))
	l.append('<a href="%s">add new entry</a>' % request.URLPath().parent().sibling("add"))

	if request.args.get('dn') \
	   and request.args.get('dn')[0]:
	    dnattr=request.args['dn'][0]
	    if request.args.get('add_'+dnattr):
		dn=dnattr+'='+request.args.get('add_'+dnattr)[0]+','+str(self.baseObject)
		l.append('<a href="%s">edit</a>' \
			 % request.URLPath().parent().sibling('edit/%s' % uriQuote(dn)))
		l.append('<a href="%s">delete</a>' \
			 % request.URLPath().parent().sibling('delete/%s' % uriQuote(dn)))
		l.append('<a href="%s">change password</a>' \
			 % request.URLPath().parent().sibling('change_password/%s' % uriQuote(dn)))

	return '[' + '|'.join(l) + ']'

    def getContent(self, request):
        a = AddForm(baseObject=self.baseObject,
                    chosenObjectClasses=[self.structuralObjectClass] + self.auxiliaryObjectClasses,
                    attributeTypes=self.attributeTypes,
                    objectClasses=self.objectClasses)
        d = defer.execute(a.display, request)
        return [self._header(request), d]

class AddPage(page.Page):
    template = '''<html>
    <head>
        <title>Ldaptor Web Interface</title>
        <style type="text/css">
.formDescription, .formError {
    /* fixme - inherit */
    font-size: smaller;
    font-family: sans-serif;
    margin-bottom: 1em;
}

.formDescription {
    color: green;
}

.formError {
    color: red;
}
</style>
    </head>
    <body>
    <h1>Ldaptor Add Page</h1>
    <div view="objectClassForm" />

    </body>
</html>'''


    def __init__(self, baseObject, attributeTypes, objectClasses):
	page.Page.__init__(self)
	self.baseObject = baseObject
        self.attributeTypes = attributeTypes
        self.objectClasses = objectClasses


        structural = []
        auxiliary = []
        for oc in self.objectClasses:
            description = oc.name[0]
            if oc.desc is not None:
                description = '%s: %s' % (description, oc.desc)
            if oc.type == 'STRUCTURAL':
                structural.append((oc.name[0], oc, description))
            elif oc.type == 'AUXILIARY':
                auxiliary.append((oc.name[0], oc, description))
                               
        self.formSignature = formmethod.MethodSignature(
            formmethod.RadioGroup(name="structuralObjectClass",
                                  shortDesc='Object type to create',
                                  choices=structural),
            formmethod.CheckGroup(name="auxiliaryObjectClasses",
                                  shortDesc='Auxiliary object classes',
                                  flags=auxiliary),
            formmethod.Submit("submit", allowNone=1),
            )

    def wvupdate_objectClassForm(self, request, widget, model):
        url = request.URLPath()
        microdom.lmx(widget.node).form(
            action=str(url.child('process')),
            method='POST',
            model="form")

    def wmfactory_form(self, request):
        return self.formSignature.method(None)

    def wchild_process(self, request):
        def process(structuralObjectClass,
                    auxiliaryObjectClasses,
                    submit=None):
            return (structuralObjectClass, auxiliaryObjectClasses)
        def callback(x):
            structuralObjectClass, auxiliaryObjectClasses = x
            structuralObjectClass = structuralObjectClass.original
            auxiliaryObjectClasses = auxiliaryObjectClasses.original
            return Redirect('+'.join([oc.name[0]
                                      for oc in ([structuralObjectClass]
                                                 + auxiliaryObjectClasses)]))
        return form.FormProcessor(
            self.formSignature.method(process),
            callback=callback,
            )

    def getDynamicChild(self, path, request):
        unquoted=uriUnquote(path)
        objectClasses = unquoted.split('+')
        assert len(objectClasses) >= 1

        structName=objectClasses[0]
        structuralObjectClass = mapNameToObjectClass(self.objectClasses,
                                                     structName)
        assert structuralObjectClass is not None, \
               "objectClass %s must have schema"%structName

        auxiliaryObjectClasses = []
        for auxName in objectClasses[1:]:
            oc = mapNameToObjectClass(self.objectClasses, auxName)
            assert oc is not None, "objectClass %s must have schema"%oc
            auxiliaryObjectClasses.append(oc)
        return ReallyAddPage(self.baseObject,
                             structuralObjectClass=structuralObjectClass,
                             auxiliaryObjectClasses=auxiliaryObjectClasses,
                             attributeTypes=self.attributeTypes,
                             objectClasses=self.objectClasses)

def getResource(baseObject, request):
    entry = request.getComponent(simpleguard.Authenticated).name
    client = entry.client
    
    d = fetchschema.fetch(client, baseObject)
    def cbAddPage(schema, baseObject):
        attributeTypes, objectClasses = schema
        return AddPage(baseObject, attributeTypes, objectClasses)
    d.addCallback(cbAddPage, baseObject)
    return DeferredResource(d)
