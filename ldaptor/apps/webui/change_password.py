from twisted.web import widgets, static
from twisted.internet import defer, protocol
from twisted.python.failure import Failure
from ldaptor.protocols.ldap import ldapsyntax
from ldaptor.protocols import pureber, pureldap
from ldaptor.apps.webui.htmlify import htmlify_attributes
from ldaptor import generate_password, ldapfilter
from twisted.internet import reactor
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote

import template

class PasswordChangeForm(widgets.Form):

    def __init__(self, dn):
	self.dn = dn

    def getFormFields(self, request):
	return  [
	    ('password', 'New password', 'password1', ''),
	    ('password', 'Again', 'password2', ''),
	    ('checkbox', 'Generate password automatically', 'generate', ''),
	    ]

    def process(self, write, request, submit,
		password1, password2, generate):
	from cStringIO import StringIO
	io=StringIO()
	self.format(self.getFormFields(request), io.write, request)

	if generate:
	    deferred=generate_password.generate(reactor)
	    deferred.addCallbacks(
		callback=self._got_password,
		callbackArgs=(request),
		errback=lambda x: x,
		)
	    return [deferred, io.getvalue()]
	else:
	    if password1 and password1==password2:
		client = request.getSession().LdaptorIdentity.getLDAPClient()
		if not client:
		    return ['<P>Password change failed: connection lost.',
			    io.getvalue()]
                o=ldapsyntax.LDAPEntry(client=client, dn=self.dn)
                d=o.setPassword(newPasswd=password1)
		d.addCallback(lambda dummy, dn=self.dn:
			      "<p>Password for <em>%s</em> has been set.</p>"%(dn))
		return [d, io.getvalue()]
	    else:
		return ['<p><strong>Passwords were different or not set.</strong></p>',
			io.getvalue()]


    def _got_password(self, passwords, request):
	assert len(passwords)==1
	pwd=passwords[0]
	client = request.getSession().LdaptorIdentity.getLDAPClient()
	if not client:
	    return ['<P>Password change failed: connection lost.']
        o=ldapsyntax.LDAPEntry(client=client, dn=self.dn)
        d=o.setPassword(newPasswd=pwd)
	d.addCallback(lambda dummy, dn, pwd:
		      "<p>Password for <em>%s</em> has been set to: <em>%s</em></p>"%(dn, pwd),
                      self.dn, pwd)
	return d

class PasswordChangePage(template.BasicPage):
    title = "Ldaptor Password Change Page"
    isLeaf = 1

    def _header(self, request):
	l=[]
	l.append('<a href="%s">Search</a>'%request.sibLink("search"))
	l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))

	if request.postpath and request.postpath!=['']:
	    l.append('<a href="%s">edit</a>' \
		     % request.sibLink("edit/" + uriUnquote(request.postpath[0])))
	    l.append('<a href="%s">delete</a>' \
		     % request.sibLink("delete/" + uriUnquote(request.postpath[0])))

	return '[' + '|'.join(l) + ']'

    def getContent(self, request):
	if not request.postpath or request.postpath==['']:
	    dn=request.getSession().LdaptorIdentity.name
	    url=request.childLink(uriQuote(dn))
	    return [static.redirectTo(url, request)]
	else:
	    dn=uriUnquote(request.postpath[0])

	    return [self._header(request),
                    '<p>Setting password for %s' % dn,
                    ] \
		   + PasswordChangeForm(dn=dn).display(request)
