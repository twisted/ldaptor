#!/usr/bin/python
import sys
from twisted.internet import app, reactor, defer
from twisted.web import server, resource
from twisted.python import log

from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector, distinguishedname
from ldaptor import ldapfilter

class Searcher(resource.Resource):
    isLeaf = 1

    def __init__(self, config):
        resource.Resource.__init__(self)
        self.config = config

    def search(self, write, search):
        if not search:
            write('Please give a search filter.')
            return defer.succeed([])

        query = ldapfilter.parseFilter(search)

        c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        d=c.connectAnonymously(self.config['base'], self.config['serviceLocationOverrides'])

        def _search(proto, base, query):
            baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=base)
            d=baseEntry.search(filterObject=query)
            return d

        d.addCallback(_search, self.config['base'], query)
        return d

    def show(self, results, write):
        for item in results:
            write('<pre>')
            write(str(item))
            write('</pre>')

    def render(self, request):
        query = request.args.get('search', [None])[0]
        d = self.search(request.write, query)
        d.addCallback(self.show, request.write)
        d.addCallback(lambda _: request.write('<p>Query was %s</p>' % query))
        d.addErrback(lambda e: request.write(str(e)))
        d.addBoth(lambda _: request.finish())
        return server.NOT_DONE_YET

def main():
    config = {
        'base': distinguishedname.DistinguishedName('ou=People,dc=example,dc=com'),
        'serviceLocationOverrides': {
        distinguishedname.DistinguishedName('dc=example,dc=com'): ('localhost', 10389),
        }
        }

    site = server.Site(Searcher(config))
    application = app.Application("LDAPressBook")
    application.listenTCP(8088, site)

    log.startLogging(sys.stdout, 0)
    application.run(save=0)

if __name__ == '__main__':
    main()
