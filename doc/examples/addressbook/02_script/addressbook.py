#!/usr/bin/python
from twisted.internet import reactor, defer

from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector, \
     distinguishedname
from ldaptor import ldapfilter

def search(config):
    c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d=c.connectAnonymously(config['base'],
                           config['serviceLocationOverrides'])

    def _doSearch(proto, config):
        searchFilter = ldapfilter.parseFilter('(gn=j*)')
        baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=config['base'])
        d=baseEntry.search(filterObject=searchFilter)
        return d

    d.addCallback(_doSearch, config)
    return d

def show(results):
    for item in results:
        print item

def main():
    import sys
    from twisted.python import log
    log.startLogging(sys.stderr, setStdout=0)

    config = {
        'base':
        distinguishedname.DistinguishedName('ou=People,dc=example,dc=com'),
        'serviceLocationOverrides': {
        distinguishedname.DistinguishedName('dc=example,dc=com'):
        ('localhost', 10389),
        }
        }

    d = search(config)
    d.addCallback(show)
    d.addErrback(defer.logError)
    d.addBoth(lambda _: reactor.stop())
    reactor.run()

if __name__ == '__main__':
    main()
