from twisted.web import widgets
from twisted.internet import defer

from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldapclient, ldaperrors
from ldaptor.protocols.ldap import schema

from cStringIO import StringIO
import urllib

import template

class DoAdd(ldapclient.LDAPAddEntry):
    def __init__(self, client, object, attributes, callback):
        ldapclient.LDAPAddEntry.__init__(self, client, object, attributes)
        self.callback=callback

    def handle_success(self):
        self.callback("<p>Success.")

    def handle_fail(self, resultCode, errorMessage):
        if errorMessage:
            msg=", "+errorMessage
        else:
            msg=""
        self.callback("<p><strong>Failed</strong>: %s%s."%(resultCode, msg))

class AddForm(widgets.Form):
    nonUserEditableAttributeTypes = {
        'objectClass': 1,
        'uidNumber': 1,
        'gidNumber': 1,
        }

    def __init__(self, baseObject,
                 chosenObjectClasses, attributeTypes, objectClasses):
        self.baseObject=baseObject
        self.chosenObjectClasses=chosenObjectClasses
        self.attributeTypes=attributeTypes
        self.objectClasses=objectClasses

    def _get_attrtype(self, name):
        for a in self.attributeTypes:
            if name in a.name:
                a.uiHint_multiline=0 #TODO
                return a
        print "attribute type %s not known"%name
        return None

    def _one_formfield(self, attr, result):
        attrtype = self._get_attrtype(attr)
        if attrtype.uiHint_multiline:
            if attrtype.single_value:
                result.append(('text', attr, 'add_'+attr, "", attrtype.desc or ''))
            else:
                result.append(('text', attr, 'add_'+attr, "", attrtype.desc or ''))
        else:
            if attrtype.single_value:
                result.append(('string', attr, 'add_'+attr, "", attrtype.desc or ''))
            else:
                # TODO maybe use a string field+button to add entries,
                # multiselection list+button to remove entries?
                result.append(('text', attr, 'add_'+attr, "", attrtype.desc or ''))

    def getFormFields(self, request, kws={}):
        r=[]

        process = {}

        # TODO sort objectclasses somehow?
        objectClasses = [request.postpath[0]]
        objectClassesSeen = {}

        dn_attribute = None
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
                if not dn_attribute:
                    dn_attribute = attr_alias
                real_attr = self._get_attrtype(str(attr_alias))

                if not self.nonUserEditableAttributeTypes.has_key(real_attr.name[0]):
                    for attr in real_attr.name:
                        if not process.has_key(attr.upper()):
                            process[attr.upper()]=0
                        if not process[attr.upper()]:
                            self._one_formfield(attr,
                                                result=r)
                        for name in real_attr.name:
                            process[name.upper()]=1

            for attr_alias in objclass.may:
                real_attr = self._get_attrtype(str(attr_alias))

                if not self.nonUserEditableAttributeTypes.has_key(real_attr.name[0]):
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
        user = request.getSession().LdaptorPerspective.getPerspectiveName()
        client = request.getSession().LdaptorIdentity.getLDAPClient()

        if not client:
            return self._output_status_and_form(
                request, kw,
                "<P>Add failed: connection lost.")

        assert kw['dn'], 'Must have dn set.'
        assert kw['add_'+kw['dn']], 'Must have attribute dn points to.'
        dn=kw['dn']+'='+kw['add_'+kw['dn']]+','+self.baseObject

        #TODO verify
        changes = [('objectClass', self.chosenObjectClasses)]
        for k,v in kw.items():
            noedit = getattr(self,
                             "nonUserEditableAttributeType_"+k,
                             None)
            if noedit:
                raise "Can't set attribute %s when adding." % k
            elif k[:len("add_")]=="add_":
                attrtype = self._get_attrtype(k[len("add_"):])
                assert attrtype

                if attrtype.single_value or attrtype.uiHint_multiline:
                    v=[v]
                else:
                    v=self._textarea_to_list(v)

                if v:
                    attr=k[len("add_"):]
                    changes.append((attr, v))
                    #TODO
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
                    changes_desc=changes_desc+"<br>adding %s: values %s"%(repr(attr), new)
            defe=defer.Deferred()
            if not mod:
                defe.callback([""])
            else:
                DoAdd(client, dn, mod, defe.callback)

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

class ChooseObjectClass(widgets.Widget):
    def __init__(self, allowedObjectClasses):
        self.allowedObjectClasses = allowedObjectClasses

    def display(self, request):
        r=['<P>Please choose an object class:\n',
           '<ul>\n']
        for oc in self.allowedObjectClasses:
            r.append('  <li><a href="%s">%s</a></li>\n'%(request.childLink(oc), oc))
        r.append('</ul>\n')
        return r

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
                l.append('<a href="%s">edit this entry</a>' \
                         % request.sibLink('edit/%s' % urllib.quote(dn)))
            
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
                           chosenObjectClasses=chosenObjectClasses,
                           attributeTypes=attributeTypes,
                           objectClasses=objectClasses).display(request))
