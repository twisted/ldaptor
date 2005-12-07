from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.protocols.ldap import fetchschema
from ldaptor.protocols.ldap import distinguishedname
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote
from ldaptor.apps.webui.i18n import _
from ldaptor.apps.webui import i18n

import os
from nevow import rend, loaders, inevow, url, tags
from formless import iformless, configurable, annotate, webform
from twisted.internet import defer

class EditStatus(object):
    def __init__(self, entry, changes):
        super(EditStatus, self).__init__()
        self.entry = entry
        self.changes = changes

multiLineAttributeTypes = {
    'description'.upper(): 1,
    }
def isAttributeTypeMultiLine(attributeType):
    for name in attributeType.name:
        if multiLineAttributeTypes.has_key(name.upper()):
            assert not attributeType.single_value
            return multiLineAttributeTypes[name.upper()]
    return 0

class EditForm(configurable.Configurable):
    nonEditableAttributes = {
        'objectClass': 1,
        }

    def __init__(self, entry, attributeTypes, objectClasses):
        super(EditForm, self).__init__(None)
        self.entry=entry
        self.attributeTypes=attributeTypes
        self.objectClasses=objectClasses

        self.formFields=self._getFormFields()

    def getBindingNames(self, ctx):
        return ['edit']

    def bind_edit(self, ctx):
        return annotate.MethodBinding(
            'edit',
            annotate.Method(arguments=self.formFields,
                            label=_('Edit')),
            action=_('Edit'))

    def _one_formfield(self, attr, values, required, result):
        if not self.nonEditableAttributes.get(attr):
            attrtype = self._get_attrtype(attr)
            if attrtype.uiHint_multiline:
                if attrtype.single_value:
                    assert len(values)==1
                    for val in values:
                        result.append(annotate.Argument(
                            'edit_'+attr,
                            annotate.Text(label=attr,
                                          description=attrtype.desc or '',
                                          default=val,
                                          required=required,
                                          )))
                        result.append(annotate.Argument(
                            'old_'+attr,
                            annotate.String(label=attr,
                                            description=attrtype.desc or '',
                                            default=val,
                                            required=required,
                                            hidden=True,
                                            )))
                else:
                    assert len(values)==1 # TODO handle multivalued multiline attributetypes
                    for val in values:
                        result.append(annotate.Argument(
                            'edit_'+attr,
                            annotate.Text(label=attr,
                                          description=attrtype.desc or '',
                                          default=val,
                                          required=required,
                                          )))
                        result.append(annotate.Argument(
                            'old_'+attr,
                            annotate.String(label=attr,
                                            description=attrtype.desc or '',
                                            default=val,
                                            required=required,
                                            hidden=True,
                                            )))
            else:
                if attrtype.single_value:
                    assert len(values)==1
                    for val in values:
                        result.append(annotate.Argument(
                            'edit_'+attr,
                            annotate.String(label=attr,
                                            description=attrtype.desc or '',
                                            default=val,
                                            required=required,
                                            )))
                        result.append(annotate.Argument(
                            'old_'+attr,
                            annotate.String(label=attr,
                                            description=attrtype.desc or '',
                                            default=val,
                                            required=required,
                                            hidden=True,
                                            )))
                else:
                    # TODO maybe use a string field+button to add entries,
                    # multiselection list+button to remove entries?
                    values=map(str, values)
                    result.append(annotate.Argument(
                        'edit_'+attr,
                        annotate.Text(label=attr,
                                      description=attrtype.desc or '',
                                      default="\n".join(values),
                                      required=required,
                                      )))
                    result.append(annotate.Argument(
                        'old_'+attr,
                        annotate.String(label=attr,
                                        description=attrtype.desc or '',
                                        default="\n".join(values),
                                        required=required,
                                        hidden=True,
                                        )))

    def _getFormFields(self):
        r=[]
        r.append(annotate.Argument('context',
                                   annotate.Context()))
        assert self.entry

        process = {}
        for k in self.entry.keys():
            process[k.upper()]=k

        # TODO sort objectclasses somehow?
        objectClasses = list(self.entry[process["OBJECTCLASS"]])
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
                        if process[attr.upper()] is not None:
                            self._one_formfield(attr,
                                                self.entry[process[attr.upper()]],
                                                required=True,
                                                result=r)
                            for name in real_attr.name:
                                process[name.upper()]=None

                if not found_one:
                    raise "Object doesn't have required attribute %s: %s"%(attr, self.entry)

            for attr_alias in objclass.may:
                found_one=0
                real_attr = self._get_attrtype(str(attr_alias))
                for attr in real_attr.name:
                    if process.has_key(attr.upper()):
                        found_one=1
                        if process[attr.upper()] is not None:
                            self._one_formfield(attr,
                                                self.entry[process[attr.upper()]],
                                                required=False,
                                                result=r)

                if not found_one:
                    # a MAY attributetype not currently present in
                    # object, but user is of course free to add it.
                    attr=str(real_attr.name[0])
                    self._one_formfield(attr,
                                        ('',),
                                        required=False,
                                        result=r)

                for name in real_attr.name:
                    process[name.upper()]=None

        assert [v is None for k,v in process.items()], "All attributes must be in objectClasses MUST or MAY: %s"%process
        return r

    def _get_attrtype(self, name):
        for a in self.attributeTypes:
            for cur in a.name:
                if name.upper() == cur.upper():
                    a.uiHint_multiline=isAttributeTypeMultiLine(a)
                    return a
        raise RuntimeError, "attribute type %s not known"%name

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

    def edit(self, context, **kw):
        entry = context.locate(inevow.ISession).getLoggedInRoot().loggedIn
        user = entry.dn

        d = defer.succeed(None)

        changes = []
        for k,v in kw.items():
            if v is None:
                v = ''
            if k[:len("edit_")]=="edit_":
                old=kw["old_"+k[len("edit_"):]]
                if old is None:
                    old = ''

                attrtype = self._get_attrtype(k[len("edit_"):])
                assert attrtype

                if attrtype.single_value or attrtype.uiHint_multiline:
                    v=v.replace('\r\n', '\n')
                    v=v.strip()
                    v=[v]
                    old=old.replace('\r\n', '\n')
                    old=old.strip()
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
            return EditStatus(self.entry, 'No changes!')

        changes_desc=tags.ul()
        newRDN = None
        for rdn in self.entry.dn.split()[0].split():
            for attr,old,new in changes:
                if (rdn.attributeType == attr
                    and rdn.value in old):
                    # Need to change the rdn
                    if newRDN is None:
                        newRDN = list(self.entry.dn.split()[0].split())
                    newRDN.remove(rdn)

                    # Try to find a replacement RDN. Possibilities are
                    # new values from the edit form and old values
                    # currently in LDAP.
                    possible = list(new)
                    possible.extend(self.entry.get(rdn.attributeType, []))
                    for o in old:
                        # Values to be removed are not acceptable as
                        # new RDN.
                        try:
                            possible.remove(o)
                        except ValueError:
                            pass
                    if not possible:
                        raise ldapsyntax.CannotRemoveRDNError \
                              (rdn.attributeType,
                               rdn.value)
                    newRDN.append(distinguishedname.LDAPAttributeTypeAndValue(attributeType=attr,
                                                                              value=possible[0]))
                    old.remove(rdn.value)
                    try:
                        new.remove(possible[0])
                    except ValueError:
                        pass
        if newRDN is not None:
            newRDN = distinguishedname.RelativeDistinguishedName(newRDN)
            changes_desc[tags.li[
                _("changing %s: changing RDN to say %s") \
                %(repr(attr), newRDN)]]
            newDN = distinguishedname.DistinguishedName(
                (newRDN,)+self.entry.dn.split()[1:]
                )
            def _move(_):
                return self.entry.move(newDN)
            d.addCallback(_move)
            def _redirect(r, ctx, newDN):
                request = inevow.IRequest(ctx)
                u = url.URL.fromContext(ctx).curdir()
                u = u.child(uriQuote(newDN))
                request.setComponent(iformless.IRedirectAfterPost, u)
                return r
            d.addCallback(_redirect, context, newDN)

        for attr,old,new in changes:
            if new:
                if self.entry.has_key(attr):
                    self.entry[attr].update(new)
                else:
                    self.entry[attr]=new
            if old:
                for x in old:
                    if x=='':
                        continue
                    self.entry[attr].remove(x)
            if old or new:
                l=tags.ul()
                changes_desc[tags.li[_("changing %s") % attr], l]
                if old:
                    l[tags.li[_("remove "), ', '.join(map(repr, old))]]
                if new:
                    l[tags.li[_("add "), ', '.join(map(repr, new))]]

        d.addCallback(lambda _: self.entry.commit())
        d.addCallback(lambda e: EditStatus(e, changes_desc))
        return d

class ReallyEditPage(rend.Page):
    addSlash = True
    docFactory = loaders.xmlfile(
        'edit-really.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self,
                 entry,
                 attributeTypes,
                 objectClasses):
        super(ReallyEditPage, self).__init__()
        self.entry = entry
        self.attributeTypes = attributeTypes
        self.objectClasses = objectClasses

    def data_css(self, ctx, data):
        u = (url.URL.fromContext(ctx).clear()
             .parentdir().parentdir().parentdir()
             .child('form.css'))
        return [ u ]

    def render_css_item(self, context, data):
        context.fillSlots('url', data)
        return context.tag

    def data_header(self, ctx, data):
        u=url.URL.fromContext(ctx)
        u=u.parentdir().parentdir().clear()
        l=[]
        l.append(tags.a(href=u.sibling("search"))[_("Search")])
        l.append(tags.a(href=u.sibling("add"))[_("add new entry")])
        return l

    def configurable_(self, context):
        a = EditForm(self.entry,
                     self.attributeTypes,
                     self.objectClasses)
        return a

    def render_form(self, context, data):
        return webform.renderForms()

    def render_passthrough(self, context, data):
        return context.tag.clear()[data]

    def render_status(self, context, data):
        try:
            obj = context.locate(inevow.IHand)
        except KeyError:
            return context.tag.clear()

        if not isinstance(obj, EditStatus):
            return context.tag.clear()[obj]

        u=url.URL.fromContext(context)
        u=u.parentdir().parentdir().clear()

        return context.tag.clear()[
            _("Edited "),
            tags.a(href=u.parentdir()
                   .child(obj.entry.dn)
                   .child("search"))[obj.entry.dn],
            _(" successfully. "),

            # TODO share implementation with entryLinks
            '[',
            tags.a(href=u.sibling('move').child(uriQuote(obj.entry.dn)))[_('move')],
            '|',
            tags.a(href=u.sibling('delete').child(uriQuote(obj.entry.dn)))[_('delete')],
            '|',
            tags.a(href=u.sibling('change_password').child(uriQuote(obj.entry.dn)))[_('change password')],
            ']',

            tags.p[obj.changes],

            ]

    render_i18n = i18n.render()

class EditPage(rend.Page):
    addSlash = True
    docFactory = loaders.xmlfile(
        'edit.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def render_url(self, ctx, data):
        u = url.URL.fromContext(ctx)
        return ctx.tag(href=u.parentdir().child('search'))

    def childFactory(self, context, name):
        dn = uriUnquote(name)
        userEntry = inevow.ISession(context).getLoggedInRoot().loggedIn

        e = ldapsyntax.LDAPEntryWithClient(dn=dn,
                                           client=userEntry.client)
        d = e.fetch()
        def _getSchema(entry):
            d = fetchschema.fetch(entry.client, entry.dn)
            def cb((attributeTypes, objectClasses), entry):
                return (entry, attributeTypes, objectClasses)
            d.addCallback(cb, entry)
            return d
        d.addCallback(_getSchema)
        def _createEditPage((entry, attributeTypes, objectClasses)):
            return ReallyEditPage(entry, attributeTypes, objectClasses)
        d.addCallback(_createEditPage)
        return d

    render_i18n = i18n.render()
