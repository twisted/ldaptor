from twisted.web import widgets
from twisted.internet import defer, protocol
from twisted.python.failure import Failure
from ldaptor.protocols.ldap import ldaperrors, ldapsyntax
from ldaptor.protocols import pureber, pureldap
from ldaptor.apps.webui.htmlify import htmlify_object
from ldaptor import generate_password, ldapfilter
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote
from twisted.internet import reactor

import template

class MassPasswordChangeForm(widgets.Form):
    def __init__(self, ldapObjects):
	self.ldapObjects = ldapObjects

    def getFormFields(self, request, kws=None):
	r=[]
	for o in self.ldapObjects:
	    safedn=o.dn #TODO
	    r.append((safedn, htmlify_object(o), 0)) #TODO
	return (
	    ('checkgroup', '',
	     'masspass', r),
	    )
    #TODO "<P>Generate new password for entries:",

    def process(self, write, request, submit, **kw):
	dnlist=kw.get('masspass', ())

	if not dnlist:
	    return ['<p>No passwords to change.']
	deferred=generate_password.generate(reactor, len(dnlist))
	deferred.addCallbacks(
	    callback=self._got_passwords,
	    callbackArgs=(dnlist, request),
	    errback=lambda x: x,
	    )
	return [deferred]

    def _got_passwords(self, passwords, dnlist, request):
	assert len(passwords)==len(dnlist)
	l=[]
	client = request.getSession().LdaptorIdentity.getLDAPClient()
	if not client:
	    return ['<P>Password change failed: connection lost.']
	for dn, pwd in zip(dnlist, passwords):
            o=ldapsyntax.LDAPEntry(client=client, dn=dn)
            d=o.setPassword(newPasswd=pwd)
	    d.addCallbacks(
		callback=(lambda dummy, dn, pwd:
			  "<p>%s&nbsp;%s</p>"%(dn, pwd)),
		callbackArgs=(dn, pwd),
		errback=lambda x: x,
		)
	    l.append(d)
	return l

class NeedFilterError(widgets.Widget):
    def display(self, request):
	return ['No filter specified. You need to use the <a href="%s">search page</a>.'%request.sibLink("search")]

class CreateError:
    def __init__(self, defe, request):
	self.deferred=defe
	self.request=request

    def __call__(self, fail):
	self.request.args['incomplete']=['true']
	self.deferred.callback(["Trouble while fetching objects from LDAP: %s.\n<HR>"%fail.getErrorMessage()])

class MassPasswordChangePage(template.BasicPage):
    title = "Ldaptor Mass Password Change Page"
    isLeaf = 1

    def __init__(self, baseObject):
	template.BasicPage.__init__(self)
	self.baseObject = baseObject

    def _header(self, request):
	l=[]
	l.append('<a href="%s">Search</a>'%request.sibLink("search"))
	l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))

	return '[' + '|'.join(l) + ']'

    def getContent(self, request):
	if not request.postpath or request.postpath==['']:
	    return NeedFilterError()
	else:
	    filtText=uriUnquote(request.postpath[0])

	    d=defer.Deferred()
	    client = request.getSession().LdaptorIdentity.getLDAPClient()
	    if client:
                o=ldapsyntax.LDAPEntry(client=client,
                                       dn=self.baseObject)
		deferred=o.search(filterText=filtText, sizeLimit=20)
		deferred.addCallbacks(
		    callback=self._getContent_2,
		    callbackArgs=(d, request),
		    errback=CreateError(d, request),
		    )
		deferred.addErrback(defer.logError)
	    else:
		CreateError(d, request)(
		    Failure(ldaperrors.LDAPUnknownError(
		    ldaperrors.other, "connection lost")))
	    return [self._header(request), d]

    def _getContent_2(self, ldapObjects, deferred, request):
	m=MassPasswordChangeForm(ldapObjects)
	x=m.display(request)
	deferred.callback(x)
