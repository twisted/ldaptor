from twisted.web import widgets
from twisted.python import defer

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient, ldaperrors

from cStringIO import StringIO

from ldaptor.apps.webui import template

class LDAPSearch_FetchByDN(ldapclient.LDAPSearch):
    def __init__(self, client, dn, callback, errback):
        ldapclient.LDAPSearch.__init__(self, client,
                                       baseObject=dn,
                                       scope=pureldap.LDAP_SCOPE_baseObject,
                                       sizeLimit=1,
                                       )
        self.callback=callback
        self.errback=errback
        self.dn=dn

        self.found=0
        self.dn=None
        self.attributes=None

    def handle_success(self):
        if self.found==0:
            self.errback(ldaperrors.other, "No such DN")
        elif self.found==1:
            self.callback(self.dn, self.attributes)
        else:
            self.errback(ldaperrors.other, "DN matched multiple entries")

    def handle_entry(self, objectName, attributes):
        self.found=self.found+1
        self.dn=objectName
        self.attributes=attributes

    def handle_fail(self, resultCode, errorMessage):
        self.errback(resultCode, errorMessage)

class DoDelete(ldapclient.LDAPDelEntry):
    def __init__(self, client, object, callback):
        ldapclient.LDAPDelEntry.__init__(self, client, object)
        self.callback=callback

    def handle_success(self):
        self.callback("<p>Success.")

    def handle_fail(self, resultCode, errorMessage):
        if errorMessage:
            msg=", "+errorMessage
        else:
            msg=""
        self.callback("<p><strong>Failed</strong>: %s%s."%(resultCode, msg))

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
        client = request.getSession().LdaptorIdentity.ldapclient

        if not client:
            return ["<P>Del failed: connection lost."]

        defe=defer.Deferred()
        DoDelete(client, self.dn, defe.callback)

        return ["<P>Submitting del as user %s.."%user, defe]

    def _header(self, request):
        return ('[<a href="%s">Search</a>'%request.sibLink("search")
                +'|<a href="%s">add new entry</a>'%request.sibLink("add")
                +']')

    def stream(self, write, request):
        write(self._header(request))
        write("<P>")
        return widgets.Form.stream(self, write, request)


class CreateDeleteForm:
    def __init__(self, defe, dn, request):
        self.deferred=defe
        self.dn=dn
        self.request=request

    def __call__(self, dn, attributes):
        self.deferred.callback(DeleteForm(dn, attributes).display(self.request))

class CreateError:
    def __init__(self, defe, dn, request):
        self.deferred=defe
        self.dn=dn
        self.request=request

    def __call__(self, resultCode=None, errorMessage=""):
        self.request.args['incomplete']=['true']
        if errorMessage:
            errorMessage=": "+errorMessage
        if resultCode!=None:
            errorMessage = str(resultCode)+errorMessage
        self.deferred.callback(["Trouble while fetching %s, got error%s.\n<HR>"%(repr(self.dn), errorMessage)])

class NeedDNError(widgets.Widget):
    def display(self, request):
        return ['No DN specified. You need to use the <a href="%s">search page</a>.'%request.sibLink("search")]

class DeletePage(template.BasicPage):
    title = "Ldaptor Del Page"
    isLeaf = 1

    def getContent(self, request):
        if not request.postpath or request.postpath==['']:
            return NeedDNError()
        else:
            dn='/'.join(request.postpath)

            d=defer.Deferred()

            client = request.getSession().LdaptorIdentity.ldapclient
            if client:
                LDAPSearch_FetchByDN(client, dn,
                                     CreateDeleteForm(d, dn, request),
                                     CreateError(d, dn, request))
            else:
                CreateError(d, dn, request)(errorMessage="connection lost")

            return [d]
