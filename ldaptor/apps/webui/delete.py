from twisted.web import widgets
from twisted.internet import defer

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldaperrors, ldapsyntax
from ldaptor.apps.webui.uriquote import uriQuote, uriUnquote

from cStringIO import StringIO

from ldaptor.apps.webui import template

class DeleteForm(widgets.Form):
    formFields = [
	# getFormFields barfs if there's nothing here
	['hidden', '', 'dummy', '', ''],
    ]

    def __init__(self, dn, attributes):
	self.dn=dn
	self.attributes=attributes

    def format(self, form, write, request):
	write('<P>You are about to delete this entry:\n')
	write('<UL>\n')
	for attr, values in self.attributes.items():
	    write('  <LI>%s:\n' % attr)
	    if len(values)==1:
                for v in values:
                    write('    %s\n' % v)
	    else:
		write('  <UL>\n')
		for val in values:
		    write('    <LI>%s</LI>\n' % val)
		write('  </UL>\n')
	    write('  </LI>\n')

	widgets.Form.format(self, form, write, request)

    def process(self, write, request, submit, **kw):
	user = request.getSession().LdaptorPerspective.getPerspectiveName()
	client = request.getSession().LdaptorIdentity.getLDAPClient()

	if not client:
	    return ["<P>Del failed: connection lost."]

	o=ldapsyntax.LDAPEntry(client=client,
                               dn=self.dn)
        d=o.delete()
        d.addCallbacks(
            callback=lambda dummy: "<p>Success.",
            errback=lambda fail: "<p><strong>Failed</strong>: %s."
            % fail.getErrorMessage())

	return ["<P>Submitting delete as user %s.."%user, d]

class CreateDeleteForm:
    def __init__(self, defe, dn, request):
	self.deferred=defe
	self.dn=dn
	self.request=request

    def __call__(self, ldapobj):
	self.deferred.callback(
	    DeleteForm(self.dn, ldapobj).display(self.request))

class CreateError:
    def __init__(self, defe, dn, request):
	self.deferred=defe
	self.dn=dn
	self.request=request

    def __call__(self, fail):
	self.request.args['incomplete']=['true']
	self.deferred.callback(["Trouble while fetching %s: %s.\n<HR>"%(repr(self.dn), fail.getErrorMessage())])

class NeedDNError(widgets.Widget):
    def display(self, request):
	return ['No DN specified. You need to use the <a href="%s">search page</a>.'%request.sibLink("search")]

class DeletePage(template.BasicPage):
    title = "Ldaptor Delete Page"
    isLeaf = 1

    def _header(self, request):
	l=[]
	l.append('<a href="%s">Search</a>'%request.sibLink("search"))
	l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))

	if request.postpath and request.postpath!=['']:
	    l.append('<a href="%s">edit</a>' \
		     % request.sibLink("edit/" + '/'.join(request.postpath)))
	    l.append('<a href="%s">change password</a>' \
		     % request.sibLink("change_password/" + '/'.join(request.postpath)))

	return '[' + '|'.join(l) + ']'

    def getContent(self, request):
	if not request.postpath or request.postpath==['']:
	    return NeedDNError()
	else:
	    dn=uriUnquote(request.postpath[0])

	    d=defer.Deferred()

	    client = request.getSession().LdaptorIdentity.getLDAPClient()
	    if client:
                o = ldapsyntax.LDAPEntry(client=client, dn=dn)
                deferred = o.fetch()
		deferred.addCallbacks(
		    CreateDeleteForm(d, dn, request),
		    CreateError(d, dn, request))
	    else:
		CreateError(d, dn, request)(errorMessage="connection lost")

	    return [self._header(request), d]
