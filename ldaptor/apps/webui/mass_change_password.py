from twisted.internet import defer
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor import generate_password
from ldaptor.apps.webui.uriquote import uriUnquote
from twisted.internet import reactor

import os
from nevow import rend, inevow, loaders, url, tags
from formless import annotate, webform, iformless, configurable

class MassPasswordChangeStatus(object):
    def __init__(self, deferlist):
        super(MassPasswordChangeStatus, self).__init__()
        self.deferlist = deferlist

class MassPasswordChangeForm(configurable.Configurable):
    def __init__(self, ldapObjects):
        super(MassPasswordChangeForm, self).__init__(None)
	self.ldapObjects = {}
        for o in ldapObjects:
            assert o.dn not in self.ldapObjects
            self.ldapObjects[o.dn] = o

        self.formFields=self._getFormFields()

    def _getFormFields(self):
	r=[]
        r.append(annotate.Argument('request',
                                   annotate.Request()))
	for dn, e in self.ldapObjects.items():
            r.append(annotate.Argument('dn_%s' % dn,
                                       annotate.Boolean(label=dn,
                                                        description=e)))
	return r

    def getBindingNames(self, ctx):
        return ['generate']

    def bind_generate(self, ctx):
        return annotate.MethodBinding(
            'generatePasswords',
            annotate.Method(arguments=self.formFields))

    def generatePasswords(self, request, **kw):
        entries = []
        for k,v in kw.items():
            if not k.startswith('dn_'):
                continue
            k = k[len('dn_'):]
            if not v:
                continue
            assert k in self.ldapObjects
            entries.append(self.ldapObjects[k])

	if not entries:
	    return 'No passwords to change.'
	d=generate_password.generate(reactor, len(entries))

        def _gotPasswords(passwords, entries):
            assert len(passwords)==len(entries)
            l=[]
            for entry, pwd in zip(entries, passwords):
                d=entry.setPassword(newPasswd=pwd)
                def _cb(entry, pwd):
                    return (entry, pwd)
                d.addCallback(_cb, pwd)
                l.append(d)
            return defer.DeferredList(l,
                                      consumeErrors=True)
        d.addCallback(_gotPasswords, entries)
        d.addCallback(MassPasswordChangeStatus)
        return d


class ReallyMassPasswordChangePage(rend.Page):
    addSlash = True
    docFactory = loaders.xmlfile(
        'mass_change_password-really.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, entries):
	super(ReallyMassPasswordChangePage, self).__init__()
	self.entries = entries

    def data_css(self, context, data):
        request = context.locate(inevow.IRequest)
        u = url.URL.fromRequest(request).clear().parent().parent().parent()
        return [
            u.child('form.css'),
            u.child('ldaptor.css'),
            ]

    def render_css_item(self, context, data):
        context.fillSlots('url', data)
        return context.tag

    def data_header(self, context, data):
        request = context.locate(inevow.IRequest)
        u=url.URL.fromRequest(request)
        u=u.parent().parent()
        l=[]
	l.append(tags.a(href=u.sibling("search"))["Search"])
	l.append(tags.a(href=u.sibling("add"))["add new entry"])
	return l

    def configurable_(self, context):
        request = context.locate(inevow.IRequest)
        return MassPasswordChangeForm(self.entries)
    
    def render_form(self, context, data):
        return webform.renderForms()[context.tag]

    def render_passthrough(self, context, data):
        return context.tag.clear()[data]

    def render_status(self, context, data):
        try:
            obj = context.locate(inevow.IHand)
        except KeyError:
            return context.tag.clear()

        if not isinstance(obj, MassPasswordChangeStatus):
            return context.tag.clear()[obj]

        dl = tags.dl(compact="compact")
        context.tag.clear()[dl]
        for success, x in obj.deferlist:
            if success:
                entry, pwd = x
                dl[tags.dt[entry.dn],
                   tags.dd[pwd]]
            else:
                context.tag['Failed: ', x.getErrorMessage()]

        return context.tag

class MassPasswordChangePage(rend.Page):
    addSlash = True
    docFactory = loaders.xmlfile(
        'mass_change_password.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, baseObject):
        super(MassPasswordChangePage, self).__init__()
        self.baseObject = baseObject

    def render_url(self, context, data):
        request = context.locate(inevow.IRequest)
        u = url.URL.fromRequest(request)
        return context.tag(href=u.parent().child('search'))

    def getDynamicChild(self, name, request):
        entry = request.getSession().getLoggedInRoot().loggedIn

        filt = uriUnquote(name)

        e=ldapsyntax.LDAPEntry(client=entry.client,
                               dn=self.baseObject)
        d=e.search(filterText=filt, sizeLimit=20)
        d.addCallback(ReallyMassPasswordChangePage)
        return d
