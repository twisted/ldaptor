from twisted.web.woven import page, simpleguard, form
from twisted.web.microdom import lmx
from twisted.python import formmethod
from twisted.web.util import Redirect
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor import weave
from ldaptor.apps.webui.uriquote import uriUnquote

class NeedDNError(Exception):
    def __str__(self):
        return 'No DN specified. You need to use the search page.'

class ConfirmDelete(page.Page):
    isLeaf = 1
    templateFile = 'delete.xhtml'

    def __init__(self, formSignature):
        page.Page.__init__(self)
        self.formSignature = formSignature

    def wmfactory_title(self, request):
        return "Ldaptor Delete Page"

    def wmfactory_header(self, request):
        l=[]
	l.append('<a href="%s">Search</a>'%request.sibLink("search"))
	l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))

	if request.postpath and request.postpath!=['']:
	    l.append('<a href="%s">edit</a>' \
		     % request.sibLink("edit/" + '/'.join(request.postpath)))
	    l.append('<a href="%s">change password</a>' \
		     % request.sibLink("change_password/" + '/'.join(request.postpath)))

	return l

    def wvupdate_form(self, request, widget, model):
        lmx(widget.node).form(model="formsignature")

    def wmfactory_formsignature(self, request):
        return self.formSignature.method(None)

    def wmfactory_entry(self, request):
	if not request.postpath or request.postpath==['']:
	    raise NeedDNError

        dn=uriUnquote(request.postpath[0])

        user = request.getComponent(simpleguard.Authenticated).name
        assert user

        entry = ldapsyntax.LDAPEntry(client=user.client, dn=dn)
        d = entry.fetch()
        return d

    def wvfactory_separatedList(self, request, node, model):
        return weave.SeparatedList(model)

class Remove(page.Page):
    isLeaf = 1
    templateFile = 'delete-done.xhtml'

    def wmfactory_header(self, request):
        l=[]
	l.append('<a href="%s">Search</a>'%request.sibLink("search"))
	l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))
	return l

    def wmfactory_delete(self, request):
        entry = request.getComponent(simpleguard.Authenticated).name
        user = entry.dn
        client = entry.client

	if not request.postpath or request.postpath==['']:
	    raise NeedDNError

        dn=uriUnquote(request.postpath[0])

	e=ldapsyntax.LDAPEntry(client=client,
                               dn=dn)
        d=e.delete()
        d.addCallbacks(
            callback=lambda dummy: "Success.",
            errback=lambda fail: "Failed: %s."
            % fail.getErrorMessage())

        return d

    def wvfactory_separatedList(self, request, node, model):
        return weave.SeparatedList(model)

def doDelete(submit):
    if submit:
        return True
    else:
        return False

def getResource():
    formSignature = formmethod.MethodSignature(
        formmethod.Submit('submit', shortDesc='Delete', allowNone=1),
        )
    class _P(form.FormProcessor):
        isLeaf=1
    def branch(doRemove):
        if doRemove:
            return Remove()
        else:
            return ConfirmDelete(formSignature)
    return _P(formSignature.method(doDelete),
              callback=branch)
