from twisted.web import widgets
from twisted.python import defer
from ldaptor.protocols.ldap import ldapclient
from ldaptor.protocols import pureber, pureldap
from twisted.internet import tcp
import string, urllib

import template

class LDAPSearchEntry(ldapclient.LDAPSearch):
    def __init__(self,
                 client,
                 callback,
                 baseObject,
                 filter=pureldap.LDAPFilterMatchAll):
        ldapclient.LDAPSearch.__init__(self, client,
                                       baseObject=baseObject,
                                       filter=filter,
                                       sizeLimit=20,
                                       )
        self.result=""
        self.callback=callback
        self.count=0

    def handle_success(self):
        self.callback(["<p>%d entries matched."%self.count])

    def handle_entry(self, objectName, attributes):
        result = ('<p>%s\n'%objectName
                  + ' [<a href="edit/%s">edit</a>\n'%urllib.quote(objectName)
                  + ' |<a href="delete/%s">delete</a>]\n'%urllib.quote(objectName)
                  + '<ul>\n'
                  )

        for a,l in attributes:
            assert len(l)>0
            if len(l)==1:
                result=result+"  <li>%s: %s\n"%(a, l[0])
            else:
                result=result+"  <li>%s:\n    <ul>\n"%a
                for i in l:
                    result=result+"      <li>%s\n"%i
                result=result+"    </ul>\n"

        result=result+"</ul>\n"

        c=self.callback
        d=defer.Deferred()
        self.callback=d.callback
        c([result, d])
        self.count=self.count+1

    def handle_fail(self, resultCode, errorMessage):
        self.callback(["fail: %d: %s"%(resultCode, errorMessage or "Unknown error")])

class DoSearch(ldapclient.LDAPClient):
    def __init__(self, callback, baseObject, searchFor=[]):
        ldapclient.LDAPClient.__init__(self)
        self.callback=callback
        self.baseObject=baseObject
        self.searchFor=searchFor

    def connectionMade(self):
        self.bind()

    def connectionFailed(self):
        self.callback(["establishing connection to LDAP server failed."])

    def connectionLost(self):
        print "DoSearch.connectionLost()"
        # TODO test before adding this one?
        #    self.callback(["connection to LDAP server lost."])

    def handle_bind_fail(self, resultCode, errorMessage):
        self.callback(["establishing connection to LDAP server failed in bind."])
        sulf.unbind()

    def handle_bind_success(self, matchedDN, serverSaslCreds):
        filt=[]
        for k,v in self.searchFor:
            v=string.strip(v)
            if v=='':
                pass
            elif v=='*':
                filt.append(pureldap.LDAPFilter_present(k))
            elif v[0]=='*' and v[-1]=='*':
                filt.append(
                    pureldap.LDAPFilter_substrings(
                    type=k,
                    substrings=[pureldap.LDAPFilter_substrings_any(v[1:-1])]))
            elif v[0]=='*':
                filt.append(
                    pureldap.LDAPFilter_substrings(
                    type=k,
                    substrings=[pureldap.LDAPFilter_substrings_final(v[1:])]))
            elif v[-1]=='*':
                filt.append(
                    pureldap.LDAPFilter_substrings(
                    type=k,
                    substrings=[pureldap.LDAPFilter_substrings_initial(v[:-1])]))
            else:
                filt.append(
                    pureldap.LDAPFilter_equalityMatch(
                    attributeDesc=pureldap.LDAPAttributeDescription(k),
                    assertionValue=pureldap.LDAPAssertionValue(v)))
        if filt:
            if len(filt)==1:
                filt=filt[0]
            else:
                filt=pureldap.LDAPFilter_and(filt)
        else:
            filt=pureldap.LDAPFilterMatchAll
        LDAPSearchEntry(self, self.callback,
                        baseObject=self.baseObject,
                        filter=filt)

class SearchForm(widgets.Form):
    formFields = [
        ('string', 'Name', 'search_cn', ''),
        ('string', 'UserID', 'search_uid', ''),
        ('string', 'Email', 'search_mail', ''),
        #('string', 'Advanced', 'ldapfilter', ''),
        ]

    def __init__(self, baseObject, ldaphost='localhost', ldapport=389):
        self.baseObject = baseObject
        self.ldaphost = ldaphost
        self.ldapport = ldapport

    def getFormFields(self, request, kws=None):
        #TODO widgets.Form.getFormFields would be nicer
        # if it tried to get values from request; but that
        # parsing happens elsewhere, need to share code
        # and preferably results too.
        if kws==None:
            kws={}
        r=[]
        for (inputType, displayName, inputName, inputValue) in self.formFields:
            if kws.has_key(inputName):
                inputValue=kws[inputName]
            r.append((inputType, displayName, inputName, inputValue))
        return r

    def process(self, write, request, submit, **kw):
        from cStringIO import StringIO
        io=StringIO()
        self.format(self.getFormFields(request, kw), io.write, request)
        d=defer.Deferred()
        searchFields=[]
        for k,v in kw.items():
            if k[:len("search_")]=="search_":
                searchFields.append((k[len("search_"):], v))
        tcp.Client(self.ldaphost, self.ldapport,
                   DoSearch(d.callback,
                            baseObject=self.baseObject,
                            searchFor=searchFields))
        return [self._header(request), io.getvalue(), d]

    def _header(self, request):
        return ('[<a href="%s">Search</a>'%request.sibLink("search")
                +'|<a href="%s">add new entry</a>'%request.sibLink("add")
                +']')

    def stream(self, write, request):
        write(self._header(request))
        write("<P>")
        return widgets.Form.stream(self, write, request)

class SearchPage(template.BasicPage):
    title = "Ldaptor Search Page"
    isLeaf = 1

    def __init__(self, baseObject, ldaphost='localhost', ldapport=389):
        template.BasicPage.__init__(self)
        self.baseObject = baseObject
        self.ldaphost = ldaphost
        self.ldapport = ldapport

    def getContent(self, request):
        return SearchForm(baseObject=self.baseObject,
                          ldaphost=self.ldaphost,
                          ldapport=self.ldapport)

