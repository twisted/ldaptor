from twisted.web import widgets
from twisted.internet import defer

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldaperrors
from ldaptor.protocols.ldap import schema

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
            raise LDAPUnknownError(ldaperrors.other, "No such DN")
        elif self.found==1:
            return self.attributes
        else:
            raise LDAPUnknownError(ldaperrors.other,
                                   "DN matched multiple entries")

    def handle_entry(self, objectName, attributes):
        self.found=self.found+1
        self.dn=objectName
        self.attributes=attributes

class DoModify(ldapclient.LDAPModifyAttributes):
    def __init__(self, client, object, modification, callback):
        ldapclient.LDAPModifyAttributes.__init__(self, client, object, modification)
        self.callback=callback

    def handle_success(self):
        self.callback("<p>Success.")

    def handle_fail(self, resultCode, errorMessage):
        if errorMessage:
            msg=", "+errorMessage
        else:
            msg=""
        self.callback("<p><strong>Failed</strong>: %s%s."%(resultCode, msg))

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
        self.dn=dn

        self.attributes={}
        for k,vs in attributes:
            k=str(k)
            vs=map(str, vs)
            assert not self.attributes.has_key(k)
            self.attributes[k]=vs

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
                    result.append(('text', attr, 'edit_'+attr, values[0], attrtype.desc or ''))
                    result.append(('hidden', '', 'old_'+attr, values[0]))
                else:
                    assert len(values)==1 # TODO handle multivalued multiline attributetypes
                    result.append(('text', attr, 'edit_'+attr, values[0], attrtype.desc or ''))
                    result.append(('hidden', '', 'old_'+attr, values[0]))
            else:
                if attrtype.single_value:
                    assert len(values)==1
                    result.append(('string', attr, 'edit_'+attr, values[0], attrtype.desc or ''))
                    result.append(('hidden', '', 'old_'+attr, values[0]))
                else:
                    # TODO maybe use a string field+button to add entries,
                    # multiselection list+button to remove entries?
                    values=map(str, values)
                    result.append(('text', attr, 'edit_'+attr, "\n".join(values), attrtype.desc or ''))
                    result.append(('hidden', '', 'old_'+attr, "\n".join(values)))

    def getFormFields(self, request, kws={}):
        r=[]
        assert self.attributes

        process = {}
        for k,v in self.attributes.items():
            process[k.upper()]=k

        # TODO sort objectclasses somehow?
        objectClasses = list(self.attributes[process["OBJECTCLASS"]])
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
                                                self.attributes[process[attr.upper()]],
                                                result=r)
                            for name in real_attr.name:
                                process[name.upper()]=None

                if not found_one:
                    raise "Object doesn't have required attribute %s: %s"%(attr, self.attributes)

            for attr in objclass.may:
                attr=str(attr)
                if process.has_key(attr.upper()) \
                   and process[attr.upper()]!=None:
                    self._one_formfield(attr, self.attributes[process[attr.upper()]],
                                        result=r)
                    process[attr.upper()]=None

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
            changes_desc=""
            mod=[]
            for attr,old,new in changes:
                if new:
                    self.attributes[attr].extend(new)
                    mod.append(pureldap.LDAPModification_add(vals=((attr, new),)))
                if old:
                    for x in old: self.attributes[attr].remove(x)
                    mod.append(pureldap.LDAPModification_delete(vals=((attr, old),)))
                if old:
                    changes_desc=changes_desc+"<br>changing %s: remove %s"%(repr(attr), old)
                if new:
                    changes_desc=changes_desc+"<br>changing %s: add %s"%(repr(attr), new)
            defe=defer.Deferred()
            if not mod:
                defe.callback([""])
            else:
                DoModify(client, self.dn, mod, defe.callback)

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
    def __init__(self, defe, dn, request):
        self.deferred=defe
        self.dn=dn
        self.request=request

    def __call__(self, fail):
        self.request.args['incomplete']=['true']
        self.deferred.callback(["Trouble while fetching %s: %s.\n<HR>"%(repr(self.dn), fail.getErrorMessage)])

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
                     % request.sibLink("delete/" + '/'.join(request.postpath)))
            l.append('<a href="%s">change password</a>' \
                     % request.sibLink("change_password/" + '/'.join(request.postpath)))
        
        return '[' + '|'.join(l) + ']'

    def getContent(self, request):
        if not request.postpath or request.postpath==['']:
            return NeedDNError()
        else:
            dn='/'.join(request.postpath)

            d=defer.Deferred()

            client = request.getSession().LdaptorIdentity.getLDAPClient()
            if client:
                deferred=defer.Deferred()
                schema.LDAPGet_subschemaSubentry(deferred, client, dn)
                deferred.addCallbacks(
                    callback=self._getContent_2,
                    callbackArgs=(dn, request, client, d),
                    errback=CreateError(d, dn, request),
                    )
                deferred.addErrback(defer.logError)
            else:
                CreateError(d, dn, request)(
                    Failure(LDAPUnknownError(ldaperrors.other,
                                             "connection lost")))

            return [self._header(request), d]

    def _getContent_2(self, subschemaSubentry, dn, request, client, d):
        deferred=defer.Deferred()

        schema.LDAPGetSchema(
            deferred,
            client, subschemaSubentry,
            )
        deferred.addCallbacks(
            callback=self._getContent_3,
            callbackArgs=(dn, request, client, d),
            errback=CreateError(d, dn, request),
            )

    def _getContent_3(self, x, dn, request, client, d):
        attributeTypes, objectClasses = x
        deferred=defer.Deferred()
        LDAPSearch_FetchByDN(deferred, client, dn)
        deferred.addCallbacks(
            callback=CreateEditForm(d, dn, request,
                                    attributeTypes, objectClasses),
            errback=CreateError(d, dn, request))
