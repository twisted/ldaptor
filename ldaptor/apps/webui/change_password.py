from twisted.internet import reactor
from twisted.web import static, html
from twisted.web.woven import simpleguard
from twisted.web.woven import page, simpleguard, form, model
from twisted.web.microdom import lmx
from twisted.python import formmethod
from twisted.internet import defer
from twisted.web.util import Redirect
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor import generate_password
from ldaptor import weave
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote

class NeedDNError(Exception):
    def __str__(self):
        return 'No DN specified. You need to use the search page.'

class PasswordMissingError(Exception):
    def __str__(self):
        return 'The password is missing.'

class PasswordsDifferError(Exception):
    def __str__(self):
        return 'The passwords entered are different.'


class ConfirmChange(page.Page):
    isLeaf = 1
    templateFile = 'change_password.xhtml'

    def __init__(self, formSignature, args):
        page.Page.__init__(self)
        self.formSignature = formSignature
        self.args = args

    def wmfactory_header(self, request):
        l=[]
	l.append('<a href="%s">Search</a>'%request.sibLink("search"))
	l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))

	if request.postpath and request.postpath!=['']:
	    l.append('<a href="%s">edit</a>' \
		     % request.sibLink("edit/" + request.postpath[0]))
	    l.append('<a href="%s">delete</a>' \
		     % request.sibLink("delete/" + request.postpath[0]))

	return l

    def wmfactory_dn(self, request):
	if not request.postpath or request.postpath==['']:
	    raise NeedDNError

        dn=uriUnquote(request.postpath[0])
        return distinguishedname.DistinguishedName(dn)

    def wvupdate_form(self, request, widget, model):
        lmx(widget.node).form(model="formsignature")

    def wmfactory_formsignature(self, request):
        return self.formSignature.method(None)

    def wvfactory_separatedList(self, request, node, model):
        return weave.SeparatedList(model)

    def wmfactory_submit(self, request):
        x=self.args.get('submit', False)
        if x is None:
            x=False
        return x

    def wmfactory_generate(self, request):
	return self.args.get('generate', False)

    def _extractPassword(self):
        password1 = self.args.get('password1', '')
        password2 = self.args.get('password2', '')

        if not password1:
            raise PasswordMissingError
        if password1!=password2:
            raise PasswordsDifferError
        return password1

    def _htmlifyExceptions(self, reason, prefix='', errorTypes=None):
        if errorTypes is not None:
            reason.trap(*errorTypes)
        return '<strong>'+prefix+html.escape(reason.getErrorMessage())+'</strong>'

    def wmfactory_setPassword(self, request):
        """Set the user-inputted password."""
        d=defer.maybeDeferred(self._extractPassword)
        d.addCallback(self._setPassword, request)
        d.addErrback(self._htmlifyExceptions,
                     errorTypes=[PasswordMissingError, PasswordsDifferError])
        return d

    def _getNewPass(self, request):
        d=generate_password.generate(reactor)
        def _first(passwords):
            assert len(passwords)==1
            return passwords[0]
        d.addCallback(_first)
        return d

    def wmfactory_generatePassword(self, request):
        d=self._getNewPass(request)
        d.addCallback(self._gotPass, request)
        return d

    def _gotPass(self, password, request):
        d = self._setPassword(password, request)
        d.addCallback(lambda status:
                      { 'password': html.escape(password),
                        'status': status,
                        })
        return d

    def _setPassword(self, password, request):
        entry = request.getComponent(simpleguard.Authenticated).name
        user = entry.dn
        client = entry.client

	if not request.postpath or request.postpath==['']:
	    raise NeedDNError

        dn=uriUnquote(request.postpath[0])

	e=ldapsyntax.LDAPEntry(client=client,
                               dn=dn)
        d=defer.maybeDeferred(e.setPassword, newPasswd=password)
        d.addCallback(lambda dummy: "Success.")
        d.addErrback(self._htmlifyExceptions,
                     prefix="Failed: ")
        return d

    def wvupdate_if(self, request, widget, model):
        if not model:
            while 1:
                c=widget.node.firstChild()
                if c is None:
                    break
                widget.node.removeChild(c)

    def wvupdate_ifNot(self, request, widget, model):
        return self.wvupdate_if(request, widget, not model)

    def render(self, request):
        if not request.postpath or request.postpath==['']:
            entry = request.getComponent(simpleguard.Authenticated).name
            dn = entry.dn
	    url=request.childLink(uriQuote(dn))
	    return static.redirectTo(url, request)
	else:
            return page.Page.render(self, request)

def doChange(**kw):
    return kw

def getResource():
    formSignature = formmethod.MethodSignature(
        formmethod.Password('password1', shortDesc='New password', allowNone=1),
        formmethod.Password('password2', shortDesc='Again', allowNone=1),
        formmethod.Boolean('generate', shortDesc='Generate password automatically', allowNone=1),
        formmethod.Submit('submit', shortDesc='Set password', allowNone=1),
        )
    class _P(form.FormProcessor):
        isLeaf=1
    def branch(args):
        assert isinstance(args, model.DictionaryModel)
        return ConfirmChange(formSignature, args.orig)
    return _P(formSignature.method(doChange),
              callback=branch)
