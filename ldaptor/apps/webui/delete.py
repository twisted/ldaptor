from twisted.web.util import Redirect
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor.apps.webui.uriquote import uriUnquote
from ldaptor import weave

import os
from nevow import rend, inevow, loaders, url, tags
from formless import annotate, webform, iformless

class IDelete(annotate.TypedInterface):
    def delete(self, request=annotate.Request()):
        pass
    delete = annotate.autocallable(delete)

class ErrorWrapper:
    def __init__(self, value):
        self.value = value

class ConfirmDelete(rend.Page):
    __implements__ = rend.Page.__implements__, IDelete
    docFactory = loaders.xmlfile(
        'delete.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, dn):
        super(ConfirmDelete, self).__init__()
        self.dn = dn

    def data_css(self, context, data):
        request = context.locate(inevow.IRequest)
        u = (url.URL.fromRequest(request).clear().parent().parent()
             .child('form.css'))
        return [ u ]

    def render_css_item(self, context, data):
        context.fillSlots('url', data)
        return context.tag

    def delete(self, request):
        user = request.getSession().getLoggedInRoot().loggedIn
	e=ldapsyntax.LDAPEntry(client=user.client,
                               dn=self.dn)
        d=e.delete()
        d.addCallbacks(
            callback=lambda _: "Success.",
            errback=lambda fail: "Failed: %s."
            % fail.getErrorMessage())
        def _redirect(_):
            u = url.URL.fromRequest(request)
            u = u.child('deleted')
            request.setComponent(iformless.IRedirectAfterPost, u)
            return _
        d.addBoth(_redirect)
        return d

    def child_deleted(self, request):
        return Deleted(self.dn)

    def data_entry(self, context, data):
        user = context.locate(inevow.ISession).getLoggedInRoot().loggedIn
        assert user

        entry = ldapsyntax.LDAPEntry(client=user.client, dn=self.dn)
        d = entry.fetch()
        d.addErrback(ErrorWrapper)
        return d

    def render_error_or_pass(self, context, data):
        if isinstance(data, ErrorWrapper):
            return context.tag.clear() \
                   [ tags.strong(style="color: red;") \
                     [ 'An error occurred: ',
                       data.value.getErrorMessage(),
                       ]
                     ]
        else:
            return context.tag

    def data_dn(self, context, data):
        return self.dn

    def render_form(self, context, data):
        return webform.renderForms()

    def render_passthrough(self, context, data):
        return context.tag.clear()[data]

    def data_header(self, context, data):
        request = context.locate(inevow.IRequest)
        u=url.URL.fromRequest(request)
        u=u.parent().parent()
        l=[]
	l.append(tags.a(href=u.sibling("search"))["Search"])
	l.append(tags.a(href=u.sibling("add"))["add new entry"])
        l.append(tags.a(href=u.sibling("edit").child(str(self.dn)))["edit"])
        l.append(tags.a(href=u.sibling("delete").child(str(self.dn)))["delete"])
	return l

    def render_keyvalue(self, context, data):
        return weave.keyvalue(context, data)

    def render_keyvalue_item(self, context, data):
        return weave.keyvalue_item(context, data)

class Deleted(rend.Page):
    docFactory = loaders.xmlfile(
        'delete-done.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self, dn):
        super(Deleted, self).__init__()
        self.dn = dn

    def data_dn(self, context, data):
        return self.dn

    def data_header(self, context, data):
        request = context.locate(inevow.IRequest)
        u=url.URL.fromRequest(request)
        u=u.parent().parent()
        l=[]
	l.append(tags.a(href=u.sibling("search"))["Search"])
	l.append(tags.a(href=u.sibling("add"))["add new entry"])
        return l

    def render_passthrough(self, context, data):
        return context.tag.clear()[data]

    def data_status(self, context, data):
        try:
            return context.locate(inevow.IStatusMessage)
        except KeyError:
            return 'Internal error, no status to display.'

class GetDN(rend.Page):
    docFactory = loaders.xmlfile(
        'delete-nodn.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def render_url(self, context, data):
        request = context.locate(inevow.IRequest)
        u = url.URL.fromRequest(request)
        return context.tag(href=u.parent().child('search'))

    def locateChild(self, request, segments):
        ret = super(GetDN, self).locateChild(request, segments)
        if ret != rend.NotFound:
            return ret

        path = segments[0]
        unquoted=uriUnquote(path)
        try:
            dn = distinguishedname.DistinguishedName(stringValue=unquoted)
        except distinguishedname.InvalidRelativeDistinguishedName, e:
            # TODO There's no way to throw a FormException at this stage.
            u = url.URL.fromRequest(request)
            # TODO freeform_post!configurableName!methodName
            u.add('dn', path)
            return Redirect(str(u)), []
        r=ConfirmDelete(dn=dn)
        return r, segments[1:]

def getResource():
    return GetDN()
