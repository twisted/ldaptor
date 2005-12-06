from zope.interface import implements
from twisted.internet import defer
from twisted.python import plugin

from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor.protocols.ldap import fetchschema
from ldaptor import numberalloc, interfaces
from ldaptor.apps.webui import iwebui
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote
from ldaptor.apps.webui.i18n import _
from ldaptor.apps.webui import i18n

import os
from nevow import rend, inevow, loaders, url, tags
from formless import annotate, webform, iformless, configurable

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

class AddOCForm(configurable.Configurable):
    def __init__(self, objectClasses):
        super(AddOCForm, self).__init__(None)
        structural = []
        auxiliary = []
        for oc in objectClasses:
            if oc.type == 'STRUCTURAL':
                structural.append(oc)
            elif oc.type == 'AUXILIARY':
                auxiliary.append(oc)
        structural.sort()
        auxiliary.sort()


        class KludgeNevowChoice(object):
            """
            A kludge that allows using Choice with both Nevow 0.3 and
            newer.
            """
            def __init__(self, oc):
                self.name = oc.name
                self.desc = oc.desc
            def __str__(self):
                """
                For Choice in Nevow 0.4 and newer. Nevow 0.3 will use
                integer indexes. Actual stringification for display
                purposes happens in strObjectClass.
                """
                return self.name[0]

        formFields = [
            annotate.Argument('ctx',
                              annotate.Context()),
            annotate.Argument('request',
                              annotate.Request()),
            annotate.Argument('structuralObjectClass',
                              annotate.Choice(label=_('Object type to create'),
                                              choices=[KludgeNevowChoice(x) for x in structural],
                                              stringify=strObjectClass)),
            ]
        for oc in auxiliary:
            formFields.append(annotate.Argument(
                'auxiliary_%s' % oc.name[0],
                annotate.Boolean(label=oc.name[0],
                                 description=oc.desc or '')))
        self.formFields = formFields

    def getBindingNames(self, ctx):
        return ['add']

    def bind_add(self, ctx):
        return annotate.MethodBinding(
            'add',
            annotate.Method(arguments=self.formFields,
                            label=_('Add')),
            action=_('Add'))

    def add(self, ctx, request, structuralObjectClass, **kw):
        assert structuralObjectClass is not None
        structuralObjectClass = str(structuralObjectClass)
        auxiliaryObjectClasses = []
        for k,v in kw.items():
            assert k.startswith('auxiliary_')
            if k.startswith('auxiliary_'):
                k = k[len('auxiliary_'):]
                if v:
                    auxiliaryObjectClasses.append(k)
        u = url.URL.fromContext(ctx)
        u = u.child('manual').child('+'.join([structuralObjectClass]
                                             + auxiliaryObjectClasses))
        return u

class AddForm(configurable.Configurable):
    def __init__(self, chosenObjectClasses, attributeTypes, objectClasses):
        super(AddForm, self).__init__(None)
        self.chosenObjectClasses=chosenObjectClasses
        self.nonUserEditableAttributeType_objectClass=[
            oc.name[0] for oc in self.chosenObjectClasses]
        self.attributeTypes=attributeTypes
        self.objectClasses=objectClasses
        self.formFields=self._getFormFields()

    def _nonUserEditableAttributeType_getFreeNumber(self, attributeType, context):
        cfg = context.locate(interfaces.ILDAPConfig)
        entry = context.locate(inevow.ISession).getLoggedInRoot().loggedIn
        client = entry.client
        o=ldapsyntax.LDAPEntry(client=client,
                               dn=cfg.getBaseDN())
        d=numberalloc.getFreeNumber(ldapObject=o,
                                    numberType=attributeType,
                                    min=1000)
        d.addCallback(lambda x, a=attributeType: (a, [str(x)]))
        return d

    nonUserEditableAttributeType_uidNumber=_nonUserEditableAttributeType_getFreeNumber
    nonUserEditableAttributeType_gidNumber=_nonUserEditableAttributeType_getFreeNumber

    def _get_attrtype(self, name):
        for a in self.attributeTypes:
            for cur in a.name:
                if name.upper() == cur.upper():
                    a.uiHint_multiline=0 #TODO
                    return a
        raise UnknownAttributeType, name

    def _one_formfield(self, attr, result, must=False):
        attrtype = self._get_attrtype(attr)
        name=attr
        if must:
            name=name+"*"
        if attrtype.uiHint_multiline:
            if attrtype.single_value:
                typed = annotate.Text(label=name,
                                      description=attrtype.desc or '',
                                      required=must)
            else:
                typed = annotate.Text(label=name,
                                      description=attrtype.desc or '',
                                      required=must)
        else:
            if attrtype.single_value:
                typed = annotate.String(label=name,
                                        description=attrtype.desc or '',
                                        required=must)
            else:
                # TODO maybe use a string field+button to add entries,
                # multiselection list+button to remove entries?
                typed = annotate.Text(label=name,
                                      description=attrtype.desc or '',
                                      required=must)

        result.append(annotate.Argument('add_'+attr, typed))

    def _getFormFields(self):
        r=[]
        r.append(annotate.Argument('context',
                                   annotate.Context()))

        process = {}

        # TODO sort objectclasses somehow?
        objectClasses = list(self.chosenObjectClasses)
        objectClassesSeen = {}

        self.nonUserEditableAttributes = []
        while objectClasses:
            objectClass = objectClasses.pop()
            objclassName = objectClass.name[0]

            if objectClassesSeen.has_key(objclassName):
                continue
            objectClassesSeen[objclassName]=1

            for ocName in objectClass.sup or []:
                objclass = mapNameToObjectClass(self.objectClasses, ocName)
                assert objclass, "Objectclass %s must have schema" %objclassName
                objectClasses.append(objclass)

            for attr_alias in objectClass.must:
                real_attr = self._get_attrtype(str(attr_alias))

                if hasattr(self, 'nonUserEditableAttributeType_'+real_attr.name[0]):
                    self.nonUserEditableAttributes.append(real_attr.name[0])
                else:
                    for attr in real_attr.name:
                        if not process.has_key(attr.upper()):
                            process[attr.upper()]=0
                        if not process[attr.upper()]:
                            self._one_formfield(attr, result=r, must=True)
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

        assert [v==1 for k,v in process.items()], "TODO: %s"%process
        return r


    def getBindingNames(self, ctx):
        return ['add']

    def bind_add(self, ctx):
        return annotate.MethodBinding(
            'add',
            annotate.Method(arguments=self.formFields,
                            label=_('Add')),
            action=_('Add'))

    def _textarea_to_list(self, t):
        return filter(lambda x: x, [x.strip() for x in t.split("\n")])

    def _getDNAttr(self):
        attr_alias = self.chosenObjectClasses[0].must[0]
        attrType = mapNameToAttributeType(self.attributeTypes, attr_alias)
        assert attrType is not None
        dn_attribute = attrType.name[0]
        return dn_attribute

    def add(self, context, **kw):
        cfg = context.locate(interfaces.ILDAPConfig)
        dnAttr = self._getDNAttr()
        assert kw.has_key('add_'+dnAttr), 'Must have attribute dn %s points to.' % dnAttr
        assert kw['add_'+dnAttr], 'Attribute %s must have value.' % 'add_'+dnAttr
        # TODO ugly
        rdn=distinguishedname.RelativeDistinguishedName(
            attributeTypesAndValues=[
            distinguishedname.LDAPAttributeTypeAndValue(attributeType=dnAttr,
                                                        value=kw['add_'+dnAttr]),
            ])

        #TODO verify
        changes = []
        for k,v in kw.items():
            if hasattr(self, "nonUserEditableAttributeType_"+k):
                raise "Can't set attribute %s when adding." % k
            elif k[:len("add_")]=="add_":
                if not v:
                    continue
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
                changes.append(thing(attributeType, context))
            else:
                changes.append(defer.succeed((attributeType, thing)))

        dl=defer.DeferredList(changes, fireOnOneErrback=1)
        #dl.addErrback(lambda x: x[0]) # throw away index
        def _pruneSuccessFlags(l):
            r=[]
            for succeeded,result in l:
                assert succeeded
                r.append(result)
            return r

        dl.addCallback(_pruneSuccessFlags)
        dl.addCallback(self._process2, context, rdn, kw)
        return dl

    def _process2(self, changes, context, rdn, kw):
        cfg = context.locate(interfaces.ILDAPConfig)
        user = context.locate(inevow.ISession).getLoggedInRoot().loggedIn

        if not changes:
            return _("No changes!") #TODO

        changes_desc=""
        mod={}
        for attr,new in changes:
            if new:
                if attr not in mod:
                    mod[attr]=[]
                mod[attr].extend(new)
                changes_desc=changes_desc+"<br>adding %s: %s"%(repr(attr), ', '.join(map(repr, new)))

        if not mod:
            return _("No changes (2)!") #TODO

        e = ldapsyntax.LDAPEntryWithClient(client=user.client,
                                           dn=iwebui.ICurrentDN(context))
        d = e.addChild(rdn, mod)
        #d.addCallback(lambda e: "Added %s successfully." % e.dn)
        d.addErrback(lambda reason: _("Failed: %s.") % reason.getErrorMessage())
        return d

class ReallyAddPage(rend.Page):
    addSlash = True

    docFactory = loaders.xmlfile(
        'add-really.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def data_css(self, ctx, data):
        u = (url.URL.fromContext(ctx).clear().parentdir().parentdir()
             .parentdir().parentdir()
             .child('form.css'))
        return [ u ]

    def render_css_item(self, context, data):
        context.fillSlots('url', data)
        return context.tag

    def data_header(self, ctx, data):
        u=url.URL.fromContext(ctx)
        u=u.parentdir().parentdir().parentdir()
        l=[]
        l.append(tags.a(href=u.sibling("search"))[_("Search")])
        l.append(tags.a(href=u.sibling("add"))[_("add new entry")])

        return l

    def render_form(self, context, data):
        return webform.renderForms()

    def render_passthrough(self, context, data):
        return context.tag.clear()[data]

    def render_status(self, context, data):
        try:
            obj = context.locate(inevow.IHand)
        except KeyError:
            return context.tag.clear()

        e = interfaces.ILDAPEntry(obj, None)
        if e is None:
            return context.tag.clear()[obj]

        u=url.URL.fromContext(context)
        u=u.parentdir().parentdir().parentdir()

        return context.tag.clear()[
            _("Added "),
            tags.a(href=u.parentdir().child(e.dn).child("search"))[e.dn],
            _(" successfully. "),

            # TODO share implementation with entryLinks
            '[',
            tags.a(href=u.sibling('edit').child(uriQuote(e.dn)))[_('edit')],
            '|',
            tags.a(href=u.sibling('move').child(uriQuote(e.dn)))[_('move')],
            '|',
            tags.a(href=u.sibling('delete').child(uriQuote(e.dn)))[_('delete')],
            '|',
            tags.a(href=u.sibling('change_password').child(uriQuote(e.dn)))[_('change password')],
            ']',
            ]

    render_i18n = i18n.render()

class SmartObjectAddPage(ReallyAddPage):
    def __init__(self, smartObject):
        super(SmartObjectAddPage, self).__init__()
        self.smartObject = smartObject

    def configurable_(self, context):
        return self.smartObject

    def render_overview(self, ctx, data):
        return tags.invisible()

class ManualAddPage(ReallyAddPage):
    def __init__(self,
                 structuralObjectClass,
                 auxiliaryObjectClasses,
                 attributeTypes,
                 objectClasses):
        super(ManualAddPage, self).__init__()
        self.structuralObjectClass = structuralObjectClass
        self.auxiliaryObjectClasses = auxiliaryObjectClasses
        self.attributeTypes = attributeTypes
        self.objectClasses = objectClasses

    def configurable_(self, context):
        a = AddForm(chosenObjectClasses=[self.structuralObjectClass]
                    + self.auxiliaryObjectClasses,
                    attributeTypes=self.attributeTypes,
                    objectClasses=self.objectClasses)
        return a

    def render_overview(self, ctx, data):
        if self.auxiliaryObjectClasses:
            return ctx.tag.clear()[
                _('Using objectclasses %s and %s.') % (
                self.structuralObjectClass.name[0],
                ', '.join([oc.name[0] for oc in self.auxiliaryObjectClasses]),
                )]
        else:
            return ctx.tag.clear()[
                _('Using objectclass %s.') % (
                self.structuralObjectClass.name[0],
                )]

def strObjectClass(oc):
    if oc.desc is not None:
        return '%s: %s' % (oc.name[0], oc.desc)
    else:
        return '%s' % (oc.name[0],)

class ChooseSmartObject(object):
    def __init__(self, pluginNames):
        self.plugins = list(pluginNames)
        self.plugins.sort()

    def getBindingNames(self, ctx):
        return ['add']

    def bind_add(self, ctx):
        return annotate.MethodBinding(
            'add',
            annotate.Method(arguments=[
            annotate.Argument('context', annotate.Context()),
            annotate.Argument('smartObjectClass', annotate.Choice(choicesAttribute='plugins')),
            ],
                            label=_('Add')),
            action=_('Add'))

    def add(self, context, smartObjectClass):
        request = context.locate(inevow.IRequest)
        u = url.URL.fromContext(context)
        return u.child('smart').child(smartObjectClass)

class AddPage(rend.Page):
    addSlash = True

    docFactory = loaders.xmlfile(
        'add.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, attributeTypes, objectClasses):
        super(AddPage, self).__init__()
        self.attributeTypes = attributeTypes
        self.objectClasses = objectClasses

    def listPlugins(self):
        for plug in plugin.getPlugIns('ldaptor.apps.webui.smartObject'):
            yield plug.name

    def havePlugins(self):
        for plug in plugin.getPlugIns('ldaptor.apps.webui.smartObject'):
            return True
        return False

    def getPlugin(self, name):
        for plug in plugin.getPlugIns('ldaptor.apps.webui.smartObject'):
            if plug.name == name:
                return plug
        raise KeyError, name

    def data_css(self, ctx, data):
        u = (url.URL.fromContext(ctx).clear().parentdir().parentdir()
             .child('form.css'))
        return [ u ]

    def render_css_item(self, context, data):
        context.fillSlots('url', data)
        return context.tag

    def data_header(self, ctx, data):
        u=url.URL.fromContext(ctx)
        u=u.parentdir()
        l=[]
        l.append(tags.a(href=u.sibling("search"))[_("Search")])
        return l

    def configurable_objectClass(self, context):
        return AddOCForm(self.objectClasses)

    def render_objectClassForm(self, context, data):
        return webform.renderForms('objectClass')

    def configurable_smartObject(self, context):
        return ChooseSmartObject(self.listPlugins())

    def render_smartObjectForm(self, context, data):
        if self.havePlugins():
            return webform.renderForms('smartObject')
        else:
            return context.tag.clear()

    def render_passthrough(self, context, data):
        return context.tag.clear()[data]

    def locateChild(self, request, segments):
        ret = super(AddPage, self).locateChild(request, segments)
        if ret != rend.NotFound:
            return ret

        if segments[0] == 'manual':
            if not segments[1:]:
                return rend.NotFound
            path=segments[1]
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
            r = ManualAddPage(structuralObjectClass=structuralObjectClass,
                              auxiliaryObjectClasses=auxiliaryObjectClasses,
                              attributeTypes=self.attributeTypes,
                              objectClasses=self.objectClasses)
            return r, segments[2:]
        elif segments[0] == 'smart':
            if not segments[1:]:
                return rend.NotFound
            name = segments[1]
            if not name:
                return rend.NotFound
            plug = self.getPlugin(name)
            module = plug.load()
            add = module.add()
            r = SmartObjectAddPage(add)
            return r, segments[2:]
        else:
            return rend.NotFound

    render_i18n = i18n.render()

def getResource(baseObject, request):
    entry = request.getSession().getLoggedInRoot().loggedIn
    client = entry.client

    d = fetchschema.fetch(client, baseObject)
    def cbAddPage(schema):
        attributeTypes, objectClasses = schema
        return AddPage(attributeTypes, objectClasses)
    d.addCallback(cbAddPage)
    return d
