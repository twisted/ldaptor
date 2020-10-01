from twisted.internet import reactor
from twisted.web import server, resource

from ldaptor.protocols.ldap import (
    ldapclient,
    ldapsyntax,
    ldapconnector,
    distinguishedname,
)
from ldaptor import ldapfilter


class LDAPConfig:
    def __init__(self, baseDN, serviceLocationOverrides=None):
        self.baseDN = distinguishedname.DistinguishedName(baseDN)
        self.serviceLocationOverrides = {}
        if serviceLocationOverrides is not None:
            for k, v in serviceLocationOverrides.items():
                dn = distinguishedname.DistinguishedName(k)
                self.serviceLocationOverrides[dn] = v

    def getBaseDN(self):
        return self.baseDN

    def getServiceLocationOverrides(self):
        return self.serviceLocationOverrides


class AddressBookResource(resource.Resource):
    def __init__(self, config):
        resource.Resource.__init__(self)
        self.config = config
        self.putChild("", self)

    def _search(self):
        c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        d = c.connectAnonymously(
            self.config.getBaseDN(), self.config.getServiceLocationOverrides()
        )

        def _doSearch(proto):
            searchFilter = ldapfilter.parseFilter("(gn=j*)")
            baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=self.config.getBaseDN())
            d = baseEntry.search(filterObject=searchFilter)
            return d

        d.addCallback(_doSearch)
        return d

    def _show(self, results, write):
        for item in results:
            write("<pre>")
            write(str(item))
            write("</pre>")

    def render(self, request):
        d = self._search()
        d.addCallback(self._show, request.write)
        d.addErrback(lambda e: request.write(str(e)))
        d.addBoth(lambda _: request.finish())
        return server.NOT_DONE_YET


def getSite(config):
    return server.Site(AddressBookResource(config))
