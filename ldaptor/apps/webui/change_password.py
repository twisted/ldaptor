from twisted.internet import reactor
from twisted.internet import defer
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor import generate_password, entry
from ldaptor.apps.webui.uriquote import uriUnquote
from ldaptor import weave

import os, sets
from nevow import rend, inevow, loaders, url, tags
from formless import annotate, webform, iformless, configurable

def getEntry(ctx, dn):
    user = ctx.locate(inevow.ISession).getLoggedInRoot().loggedIn
    e=ldapsyntax.LDAPEntry(client=user.client, dn=dn)
    return e

def getEntryWithAttributes(ctx, dn, *attributes):
    e = getEntry(ctx, dn)
    d = e.fetch(*attributes)
    return d

class IPasswordChange(annotate.TypedInterface):
    def setPassword(self,
                    ctx=annotate.Context(),
                    newPassword=annotate.Password(required=True)):
        pass
    setPassword = annotate.autocallable(setPassword)

    def generateRandom(self,
                       ctx=annotate.Context()):
        pass
    generateRandom = annotate.autocallable(generateRandom)

class IServicePasswordChange(annotate.TypedInterface):
    def remove(self,
                      ctx=annotate.Context()):
        pass
    remove = annotate.autocallable(remove)

    def setServicePassword(self,
                           ctx=annotate.Context(),
                           newPassword=annotate.Password(required=True)):
        pass
    setServicePassword = annotate.autocallable(setServicePassword)

    def generateRandom(self,
                       ctx=annotate.Context()):
        pass
    generateRandom = annotate.autocallable(generateRandom)

class ServicePasswordChange(object):
    __implements__ = IServicePasswordChange

    def __init__(self, dn, service):
        super(ServicePasswordChange, self).__init__()
        self.dn = dn
        self.service = service

    def setServicePassword(self, ctx, newPassword):
        d = getEntryWithAttributes(ctx, self.dn, 'servicePassword')
        d.addCallback(self._cbSetPassword, newPassword)

        def _report(_, name):
            return 'Set password for service %r' % name
        d.addCallback(_report, self.service)

        return d

    def _cbSetPassword(self, e, newPassword):
        digest = entry.sshaDigest(newPassword)
        self._doRemove(e)
        e['servicePassword'].add('%s %s' % (self.service, digest))
        d = e.commit()
        return d

    def generateRandom(self, ctx):
        d=generate_password.generate(reactor)
        def _first(passwords):
            assert len(passwords)==1
            return passwords[0]
        d.addCallback(_first)

        def _status(newPassword, ctx):
            d = getEntryWithAttributes(ctx, self.dn, 'servicePassword')
            d.addCallback(self._cbSetPassword, newPassword)
            d.addCallback(lambda _: 'Service %r password set to %s' % (self.service, newPassword))
            return d
        d.addCallback(_status, ctx)

        return d

    def remove(self, ctx):
        d = getEntryWithAttributes(ctx, self.dn, 'servicePassword')
        d.addCallback(self._cbRemove)
        return d

    def _doRemove(self, e):
        remove = []
        for f in e.get('servicePassword', []):
            svc = f.split(None, 1)[0]
            if svc == self.service:
                remove.append(f)
        for f in remove:
            e['servicePassword'].remove(f)
        return remove

    def _cbRemove(self, e):
        remove = self._doRemove(e)
        if not remove:
            return 'Service %r not found, not removed.' % self.service
        else:
            d = e.commit()

            def _report(_, name):
                return 'Removed service %r' % name
            d.addCallback(_report, self.service)
            return d

class IAddService(annotate.TypedInterface):
    def add(self,
            ctx=annotate.Context(),
            serviceName=annotate.String(required=True),
            newPassword=annotate.Password(required=False,
                                          description="Leave empty to generate random password."),
            ):
        pass
    add = annotate.autocallable(add)

class AddService(object):
    __implements__ = IAddService

    def __init__(self, dn):
        super(AddService, self).__init__()
        self.dn = dn

    def add(self, ctx, serviceName, newPassword):
        d = getEntryWithAttributes(ctx, self.dn, 'servicePassword')
        if not newPassword:
            d.addCallback(self._generate, serviceName)
        else:
            d.addCallback(self._add, newPassword, serviceName)
        return d

    def _doRemove(self, e, serviceName):
        # TODO refactor to share code
        remove = []
        for f in e.get('servicePassword', []):
            svc = f.split(None, 1)[0]
            if svc == serviceName:
                remove.append(f)
        for f in remove:
            e['servicePassword'].remove(f)
        return remove

    def _cbSetPassword(self, e, newPassword, serviceName):
        digest = entry.sshaDigest(newPassword)
        self._doRemove(e, serviceName) #TODO fail if it exists?
        if 'servicePassword' not in e:
            e['servicePassword'] = []
        e['servicePassword'].add('%s %s' % (serviceName, digest))
        d = e.commit()
        return d

    def _generate(self, e, serviceName):
        d=generate_password.generate(reactor)
        def _first(passwords):
            assert len(passwords)==1
            return passwords[0]
        d.addCallback(_first)

        def _cb(newPassword, e, serviceName):
            d = self._cbSetPassword(e, newPassword, serviceName)
            d.addCallback(lambda _: 'Added service %r with password %s' % (serviceName, newPassword))
            return d
        d.addCallback(_cb, e, serviceName)

        return d

    def _add(self, e, newPassword, serviceName):
        d = self._cbSetPassword(e, newPassword, serviceName)
        def _report(_, name):
            return 'Added service %r' % name
        d.addCallback(_report, serviceName)

        return d

class ConfirmChange(rend.Page):
    __implements__ = rend.Page.__implements__, IPasswordChange
    addSlash = True

    docFactory = loaders.xmlfile(
        'change_password.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, dn):
        super(ConfirmChange, self).__init__()
        self.dn = dn

    def data_css(self, ctx, data):
        request = ctx.locate(inevow.IRequest)
        root = url.URL.fromRequest(request).clear().parent().parent().parent()
        return [
            root.child('form.css'),
            root.child('ldaptor.css'),
            ]

    def render_css_item(self, ctx, data):
        ctx.fillSlots('url', data)
        return ctx.tag

    def _prettifyExceptions(self, reason, prefix='', errorTypes=None):
        if errorTypes is not None:
            reason.trap(*errorTypes)
        return (prefix + reason.getErrorMessage())

    def _setPassword(self, ctx, password):
        e = getEntry(ctx, self.dn)
        d=defer.maybeDeferred(e.setPassword, newPasswd=password)
        return d

    def setPassword(self, ctx, newPassword):
        d = self._setPassword(ctx, newPassword)
        d.addCallback(lambda dummy: 'Password set.')
        d.addErrback(self._prettifyExceptions,
                     prefix="Failed: ")
        return d

    def generateRandom(self, ctx):
        d=generate_password.generate(reactor)
        def _first(passwords):
            assert len(passwords)==1
            return passwords[0]
        d.addCallback(_first)

        def _status(newPassword, ctx):
            d = self._setPassword(ctx, newPassword)
            d.addCallback(lambda dummy: 'Password set to %s' % newPassword)
            return d
        d.addCallback(_status, ctx)
        d.addErrback(self._prettifyExceptions,
                     prefix="Failed: ")
        return d

    def data_status(self, ctx, data):
        try:
            return ctx.locate(inevow.IStatusMessage)
        except KeyError:
            return ''

    def data_dn(self, ctx, data):
        return self.dn

    def render_form(self, ctx, data):
        return webform.renderForms()

    def render_hideIfNot(self, ctx, data):
        if data:
            return ctx.tag
        else:
            return tags.invisible()

    def data_servicePasswords(self, ctx, data):
        d = getEntryWithAttributes(ctx, self.dn, 'servicePassword')
        def _cb(e):
            seen = sets.Set()
            l = []
            for item in e.get('servicePassword', []):
                service = item.split(None, 1)[0]
                if service not in seen:
                    l.append(service)
                    seen.add(service)
            return l
        d.addCallback(_cb)
        return d

    def render_form_service(self, ctx, data):
        # TODO error messages for one password change form display in
        # all of them.
        serviceName = inevow.IData(ctx)
        return webform.renderForms('service_%s' % serviceName)[ctx.tag()]

    render_zebra = weave.zebra()

    def locateConfigurable(self, ctx, name):
        try:
            return super(ConfirmChange, self).locateConfigurable(ctx, name)
        except AttributeError:
            if name.startswith('service_'):
                pass
            else:
                raise

        service = name[len('service_'):]
        return iformless.IConfigurable(ServicePasswordChange(self.dn, service))

    def render_passthrough(self, ctx, data):
        return ctx.tag.clear()[data]

    def data_header(self, ctx, data):
        request = ctx.locate(inevow.IRequest)
        u=url.URL.fromRequest(request)
        u=u.parent().parent()
        l=[]
	l.append(tags.a(href=u.sibling("search"))["Search"])
	l.append(tags.a(href=u.sibling("add"))["add new entry"])
        l.append(tags.a(href=u.sibling("edit").child(str(self.dn)))["edit"])
        l.append(tags.a(href=u.sibling("delete").child(str(self.dn)))["delete"])
	return l

    def render_add(self, ctx, data):
        return webform.renderForms('add')

    def configurable_add(self, ctx):
        return AddService(self.dn)

class GetDN(rend.Page):
    addSlash = True

    def child_(self, ctx):
        entry = inevow.ISession(ctx).getLoggedInRoot().loggedIn
        u = inevow.IRequest(ctx).URLPath()
        return u.child(str(entry.dn))

    def childFactory(self, ctx, name):
        unquoted=uriUnquote(name)
        try:
            dn = distinguishedname.DistinguishedName(stringValue=unquoted)
        except distinguishedname.InvalidRelativeDistinguishedName, e:
            # TODO There's no way to throw a FormException at this stage.
            return None
        r=ConfirmChange(dn=dn)
        return r

def getResource():
    return GetDN()
