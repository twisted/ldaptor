from twisted.web import widgets, static
from twisted.internet import defer, protocol
from twisted.python.failure import Failure
from ldaptor.protocols.ldap import ldapclient, ldapfilter
from ldaptor.protocols import pureber, pureldap
from ldaptor.apps.webui.htmlify import htmlify_attributes
from ldaptor import generate_password
from twisted.internet import reactor
import string, urllib

import template

class PasswordChangeForm(widgets.Form):

    def __init__(self, dn):
        self.dn = dn

    def getFormFields(self, request, dn=None):
        if dn is None:
            dn=self.dn
        return  [
            ('string', 'Distinguished Name', 'dn', dn),
            ('password', 'New password', 'password1', ''),
            ('password', 'Again', 'password2', ''),
            ('checkbox', 'Generate password automatically', 'generate', ''),
            ]

    def process(self, write, request, submit,
                dn, password1, password2, generate):
        from cStringIO import StringIO
        io=StringIO()
        self.format(self.getFormFields(request, dn), io.write, request)

        if generate:
            deferred=generate_password.generate()
            deferred.addCallbacks(
                callback=self._got_password,
                callbackArgs=(dn, request),
                errback=lambda x: x,
                )
            return [deferred, io.getvalue()]
        else:
            if password1 and password1==password2:
                client = request.getSession().LdaptorIdentity.getLDAPClient()
                if not client:
                    return ['<P>Password change failed: connection lost.',
                            io.getvalue()]
                d=defer.Deferred()
                ldapclient.LDAPModifyPassword(d, client,
                                              userIdentity=dn,
                                              newPasswd=password1)
                d.addCallbacks(
                    callback=(lambda dummy, dn:
                              "<p>Password for <em>%s</em> has been set.</p>"%(dn)),
                    callbackArgs=(dn,),
                    errback=lambda x: x,
                    )
                return [d, io.getvalue()]
            else:
                return ['<p><strong>Passwords were different or not set.</strong></p>',
                        io.getvalue()]
                

    def _got_password(self, passwords, dn, request):
        assert len(passwords)==1
        pwd=passwords[0]
        client = request.getSession().LdaptorIdentity.getLDAPClient()
        if not client:
            return ['<P>Password change failed: connection lost.']
        d=defer.Deferred()
        ldapclient.LDAPModifyPassword(d, client,
                                      userIdentity=dn,
                                      newPasswd=pwd)
        d.addCallbacks(
            callback=(lambda dummy, dn, pwd:
                      "<p>Password for <em>%s</em> has been set to: <em>%s</em></p>"%(dn, pwd)),
            callbackArgs=(dn, pwd),
            errback=lambda x: x,
            )
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
                     % request.sibLink("edit/" + '/'.join(request.postpath)))
            l.append('<a href="%s">delete</a>' \
                     % request.sibLink("delete/" + '/'.join(request.postpath)))
            
        return '[' + '|'.join(l) + ']'

    def getContent(self, request):
        if not request.postpath or request.postpath==['']:
            dn=request.getSession().LdaptorIdentity.name
            url=request.childLink(urllib.quote(dn))
            return [static.redirectTo(url, request)]
        else:
            dn='/'.join(request.postpath)

            return [self._header(request)] \
                   + PasswordChangeForm(dn=dn).display(request)
