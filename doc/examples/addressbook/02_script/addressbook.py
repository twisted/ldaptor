#!/usr/bin/python
from twisted.internet import reactor

from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector, distinguishedname
from ldaptor import ldapfilter

def search(config):
    query = ldapfilter.parseFilter('(gn=j*)')

    c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d=c.connectAnonymously(config['base'], config['serviceLocationOverrides'])

    def _search(proto, base, query):
        baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=base)
        d=baseEntry.search(filterObject=query)
        return d

    d.addCallback(_search, config['base'], query)
    return d

def show(results):
    for item in results:
        print item

def main():
    config = {
        'base': distinguishedname.DistinguishedName('ou=People,dc=example,dc=com'),
        'serviceLocationOverrides': {
        distinguishedname.DistinguishedName('dc=example,dc=com'): ('localhost', 10389),
        }
        }

    d = search(config)
    d.addCallback(show)
    d.addBoth(lambda _: reactor.stop())
    reactor.run()

if __name__ == '__main__':
    main()
