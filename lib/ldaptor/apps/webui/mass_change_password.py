from twisted.web import widgets
from twisted.internet import defer, protocol
from twisted.python.failure import Failure
from ldaptor.protocols.ldap import ldapclient, ldapfilter, ldaperrors
from ldaptor.protocols import pureber, pureldap
from ldaptor.apps.webui.htmlify import htmlify_attributes
from ldaptor import generate_password
from twisted.internet import reactor
import string, urllib

import template


class LDAPSearchEntry(ldapclient.LDAPSearch):
    def __init__(self,
                 deferred,
                 client,
                 baseObject,
                 filter=pureldap.LDAPFilterMatchAll):
        self.ldapObjects=[]
        ldapclient.LDAPSearch.__init__(self, deferred, client,
                                       baseObject=baseObject,
                                       filter=filter,
                                       sizeLimit=20,
                                       )
    def handle_entry(self, objectName, attributes):
        self.ldapObjects.append((objectName, attributes))

class DoSearch(ldapclient.LDAPClient):
    factory=None

    def __init__(self):
        ldapclient.LDAPClient.__init__(self)

    def connectionMade(self):
        d=self.bind()
        d.addCallbacks(self._handle_bind_success,
                       self._handle_bind_fail)

    def _handle_bind_fail(self, fail):
        self.unbind()
        self.factory.errback(fail)

    def _handle_bind_success(self, x):
        matchedDN, serverSaslCreds = x
        LDAPSearchEntry(self.factory.deferred,
                        self,
                        baseObject=self.factory.baseObject,
                        filter=self.factory.ldapFilter)
        self.factory.deferred.addCallbacks(self._unbind, lambda x:x)

    def _unbind(self, x):
        self.unbind()
        return x

class DoSearchFactory(protocol.ClientFactory):
    protocol=DoSearch

    def __init__(self, deferred, baseObject, ldapFilter):
        self.deferred=deferred
        self.baseObject=baseObject
        self.ldapFilter=ldapFilter
        deferred.addCallbacks(self._ok, errback=lambda x:x)

    def _ok(self, dummy):
        return dummy.ldapObjects

    def clientConnectionFailed(self, connector, reason):
        self.deferred.errback(reason)

    def clientConnectionLost(self, connector, reason):
        if not self.deferred.called:
            self.deferred.errback(reason)

class MassPasswordChangeForm(widgets.Form):
    def __init__(self, ldapObjects):
        self.ldapObjects = ldapObjects

    def getFormFields(self, request, kws=None):
        r=[]
        for dn, attributes in self.ldapObjects:
            safedn=dn #TODO
            r.append((safedn, '<b>'+dn+'</b>'+htmlify_attributes(attributes), 0))
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
            d=defer.Deferred()
            ldapclient.LDAPModifyPassword(d, client,
                                          userIdentity=dn,
                                          newPasswd=pwd)
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
        self.deferred.callback(["Trouble while fetching objects from LDAP: %s.\n<HR>"%fail.getErrorMessage])

class MassPasswordChangePage(template.BasicPage):
    title = "Ldaptor Mass Password Change Page"
    isLeaf = 1

    def __init__(self, baseObject, ldaphost, ldapport):
        template.BasicPage.__init__(self)
        self.baseObject = baseObject
        self.ldaphost = ldaphost
        self.ldapport = ldapport

    def _header(self, request):
        l=[]
        l.append('<a href="%s">Search</a>'%request.sibLink("search"))
        l.append('<a href="%s">add new entry</a>'%request.sibLink("add"))
        
        return '[' + '|'.join(l) + ']'

    def getContent(self, request):
        if not request.postpath or request.postpath==['']:
            return NeedFilterError()
        else:
            filtText='/'.join(request.postpath)
            filt=ldapfilter.parseFilter(filtText)

            d=defer.Deferred()
            client = request.getSession().LdaptorIdentity.getLDAPClient()
            if client:
                deferred=defer.Deferred()
                s=DoSearchFactory(deferred, self.baseObject, filt)
                reactor.connectTCP(self.ldaphost, self.ldapport, s)
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
