from twisted.internet import reactor
from twisted.internet import defer
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor import generate_password, entry, interfaces
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

def getServiceName(ctx, dn):
    d = getEntryWithAttributes(ctx, dn, 'cn')
    def _cb(e):
        for cn in e.get('cn', []):
            return cn
        raise RuntimeError, \
              "Service password entry has no attribute cn: %r" % e
    d.addCallback(_cb)
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

class IRemoveServicePassword(annotate.TypedInterface):
    def remove(self,
               ctx=annotate.Context()):
        pass
    remove = annotate.autocallable(remove)

class ISetServicePassword(annotate.TypedInterface):
    def setServicePassword(self,
                           ctx=annotate.Context(),
                           newPassword=annotate.PasswordEntry(required=True),
                           again=annotate.PasswordEntry(required=True),
                           ):
        pass
    setServicePassword = annotate.autocallable(setServicePassword)

class ISetRandomServicePassword(annotate.TypedInterface):
    def generateRandom(self,
                       ctx=annotate.Context()):
        pass
    generateRandom = annotate.autocallable(generateRandom)

class RemoveServicePassword(object):
    __implements__ = IRemoveServicePassword

    def __init__(self, dn):
        super(RemoveServicePassword, self).__init__()
        self.dn = dn

    def remove(self, ctx):
        e = getEntry(ctx, self.dn)
        d = getServiceName(ctx, self.dn)

        def _delete(name, e):
            d = e.delete()
            d.addCallback(lambda _: name)
            return d
        d.addCallback(_delete, e)

        def _report(name):
            return 'Removed service %r' % name
        d.addCallback(_report)

        return d

class SetServicePassword(object):
    __implements__ = ISetServicePassword

    def __init__(self, dn):
        super(SetServicePassword, self).__init__()
        self.dn = dn

    def _isPasswordAcceptable(self, ctx, newPassword, again):
        if newPassword != again:
            raise annotate.ValidateError(
                {},
                formErrorMessage='Passwords do not match.')

    def setServicePassword(self, ctx, newPassword, again):
        d = defer.maybeDeferred(self._isPasswordAcceptable, ctx, newPassword, again)
        def _setPassword(ctx, dn, newPassword):
            e = getEntry(ctx, dn)
            d=defer.maybeDeferred(e.setPassword, newPasswd=newPassword)
            return d
        d.addCallback(lambda _: _setPassword(ctx, self.dn, newPassword))

        def _getName(_, ctx):
            d = getServiceName(ctx, self.dn)
            return d
        d.addCallback(_getName, ctx)

        def _report(name):
            return 'Set password for service %r' % name
        d.addCallback(_report)

        return d

class SetRandomServicePassword(object):
    __implements__ = ISetRandomServicePassword

    def __init__(self, dn):
        super(SetRandomServicePassword, self).__init__()
        self.dn = dn

    def generateRandom(self, ctx):
        d=generate_password.generate(reactor)
        def _first(passwords):
            assert len(passwords)==1
            return passwords[0]
        d.addCallback(_first)

        def _setPass(newPassword, ctx):
            e = getEntry(ctx, self.dn)
            d = e.setPassword(newPassword)

            def _getName(_, ctx):
                d = getServiceName(ctx, self.dn)
                return d
            d.addCallback(_getName, ctx)

            def _report(name, newPassword):
                return 'Service %r password set to %s' % (name, newPassword)
            d.addCallback(_report, newPassword)

            return d

        d.addCallback(_setPass, ctx)
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
        if not newPassword:
            return self._generate(ctx, serviceName)
        else:
            return self._add(ctx, newPassword, serviceName)
        return d

    def _cbSetPassword(self, ctx, newPassword, serviceName):
        e = getEntry(ctx, self.dn)
        rdn = distinguishedname.RelativeDistinguishedName(
            attributeTypesAndValues=[
            distinguishedname.LDAPAttributeTypeAndValue(
            attributeType='cn', value=serviceName),
            distinguishedname.LDAPAttributeTypeAndValue(
            attributeType='owner', value=str(self.dn))
                                     ])
        d = e.addChild(rdn, {
            'objectClass': ['serviceSecurityObject'],
            'cn': [serviceName],
            'owner': [str(self.dn)],
            'userPassword': ['{crypt}!'],
            })
        def _setPass(e, newPassword):
            d = e.setPassword(newPassword)
            return d
        d.addCallback(_setPass, newPassword)
        return d

    def _generate(self, ctx, serviceName):
        d=generate_password.generate(reactor)
        def _first(passwords):
            assert len(passwords)==1
            return passwords[0]
        d.addCallback(_first)

        def _cb(newPassword, serviceName):
            d = self._cbSetPassword(ctx, newPassword, serviceName)
            d.addCallback(lambda _: 'Added service %r with password %s' % (serviceName, newPassword))
            return d
        d.addCallback(_cb, serviceName)

        return d

    def _add(self, ctx, newPassword, serviceName):
        d = self._cbSetPassword(ctx, newPassword, serviceName)
        def _report(_, name):
            return 'Added service %r' % name
        d.addCallback(_report, serviceName)

        return d


class ServicePasswordChangeMixin(object):
    def __init__(self, dn):
        super(ServicePasswordChangeMixin, self).__init__()
        self.dn = dn

    def listServicePasswordActions(self):
        l = [(int(pri), name)
             for x, pri, name in [name.split('_', 2) for name in dir(self)
                                     if name.startswith('servicePasswordAction_')]]
        l.sort()
        for pri, name in l:
            yield name

    def getServicePasswordAction(self, name):
        for attrName in dir(self):
            if not attrName.startswith('servicePasswordAction_'):
                continue

            x, pri, actionName = attrName.split('_', 2)
                              
            if actionName == name:
                return getattr(self, attrName)
        return None

    def render_servicePasswords(self, ctx, data):
        docFactory = loaders.xmlfile(
            'change_service_passwords.xhtml',
            templateDir=os.path.split(os.path.abspath(__file__))[0])
        r = inevow.IQ(docFactory).onePattern('main')
        return r

    def render_hideIfNot(self, ctx, data):
        if data:
            return ctx.tag
        else:
            return tags.invisible()

    def data_servicePasswords(self, ctx, data):
        user = ctx.locate(inevow.ISession).getLoggedInRoot().loggedIn
        config = interfaces.ILDAPConfig(ctx)
        e=ldapsyntax.LDAPEntry(client=user.client, dn=config.getBaseDN())
        d = e.search(filterObject=pureldap.LDAPFilter_and([
            pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('objectClass'),
                                              assertionValue=pureldap.LDAPAssertionValue('serviceSecurityObject')),
            pureldap.LDAPFilter_equalityMatch(attributeDesc=pureldap.LDAPAttributeDescription('owner'),
                                              assertionValue=pureldap.LDAPAssertionValue(str(self.dn))),
            pureldap.LDAPFilter_present('cn'),
            ]),
                     attributes=['cn'])

        return d

    def render_form_service(self, ctx, data):
        # TODO error messages for one password change form display in
        # all of them.
        e = inevow.IData(ctx)
        for name in self.listServicePasswordActions():
            yield webform.renderForms('service_%s_%s' % (name, e.dn))[ctx.tag()]

    def locateConfigurable(self, ctx, name):
        try:
            return super(ServicePasswordChangeMixin, self).locateConfigurable(ctx, name)
        except AttributeError:
            if name.startswith('service_'):
                pass
            else:
                raise

        rest = name[len('service_'):]
        l = rest.split('_', 1)
        if len(l) != 2:
            raise AttributeError, name

        c = self.getServicePasswordAction(l[0])
        if c is None:
            raise AttributeError, name
        return iformless.IConfigurable(c(l[1]))


    render_zebra = weave.zebra()


class ConfirmChange(ServicePasswordChangeMixin, rend.Page):
    __implements__ = rend.Page.__implements__, IPasswordChange
    addSlash = True

    docFactory = loaders.xmlfile(
        'change_password.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    servicePasswordAction_10_remove = RemoveServicePassword
    servicePasswordAction_20_set = SetServicePassword
    servicePasswordAction_30_random = SetRandomServicePassword

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
