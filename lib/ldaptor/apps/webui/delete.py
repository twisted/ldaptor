from twisted.web import widgets
from twisted.internet import defer

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldaperrors

from cStringIO import StringIO

from ldaptor.apps.webui import template

class LDAPSearch_FetchByDN(ldapclient.LDAPSearch):
    def __init__(self, deferred, client, dn):
        ldapclient.LDAPSearch.__init__(self, deferred, client,
                                       baseObject=dn,
                                       scope=pureldap.LDAP_SCOPE_baseObject,
                                       sizeLimit=1,
                                       )
        self.found=0
        self.dn=None
        self.attributes=None
        deferred.addCallbacks(callback=self._ok,
                              errback=lambda x: x)

    def _ok(self, dummy):
        if self.found==0:
            raise ldaperrors.LDAPUnknownError(ldaperrors.other, "No such DN")
        elif self.found==1:
            return self.attributes
        else:
            raise ldaperrors.LDAPUnknownError(ldaperrors.other,
                                              "DN matched multiple entries")

    def handle_entry(self, objectName, attributes):
        self.found=self.found+1
        self.dn=objectName
        self.attributes=attributes

class DoDelete(ldapclient.LDAPDelEntry):
    def __init__(self, client, object, callback):
        ldapclient.LDAPDelEntry.__init__(self, client, object)
        self.callback=callback

    def handle_success(self):
        self.callback("<p>Success.")

    def handle_fail(self, fail):
        self.callback("<p><strong>Failed</strong>: %s."%fail.getErrorMessage())

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
        for attr, values in self.attributes:
            write('  <LI>%s:\n' % attr)
            if len(values)==1:
                write('    %s\n' % values[0])
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

        defe=defer.Deferred()
        DoDelete(client, self.dn, defe.callback)

        return ["<P>Submitting del as user %s.."%user, defe]

class CreateDeleteForm:
    def __init__(self, defe, dn, request):
        self.deferred=defe
        self.dn=dn
        self.request=request

    def __call__(self, attributes):
        self.deferred.callback(
            DeleteForm(self.dn, attributes).display(self.request))

class CreateError:
    def __init__(self, defe, dn, request):
        self.deferred=defe
        self.dn=dn
        self.request=request

    def __call__(self, fail):
        self.request.args['incomplete']=['true']
        self.deferred.callback(["Trouble while fetching %s: %s.\n<HR>"%(repr(self.dn), fail.getErrorMessage)])

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
            dn='/'.join(request.postpath)

            d=defer.Deferred()

            client = request.getSession().LdaptorIdentity.getLDAPClient()
            if client:
                deferred=defer.Deferred()
                LDAPSearch_FetchByDN(deferred, client, dn)
                deferred.addCallbacks(
                    CreateDeleteForm(d, dn, request),
                    CreateError(d, dn, request))
            else:
                CreateError(d, dn, request)(errorMessage="connection lost")

            return [self._header(request), d]
