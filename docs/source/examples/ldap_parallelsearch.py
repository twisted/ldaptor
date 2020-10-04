#!/usr/bin/env python3
from ldaptor.protocols.ldap import (
    ldapclient,
    ldapsyntax,
    ldapconnector,
    distinguishedname,
)
from twisted.internet import defer, reactor
from twisted.python import log
import sys

exitStatus = 0


def error(fail):
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


def _handle_entry(entry, connection, search):
    sys.stdout.write("# connection %d, search %d\n%s" % (connection, search, entry))


def _search(proto, base, connection, numOfSearches):
    l = []
    baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=base)
    for search in range(0, numOfSearches):
        d = baseEntry.search(callback=lambda x: _handle_entry(x, connection, search))
        d.addErrback(error)
        l.append(d)

    dl = defer.DeferredList(l)
    return dl


def main(base, serviceLocationOverrides, numOfConnections=3, numOfSearches=3):
    log.startLogging(sys.stderr, setStdout=0)
    l = []
    for connection in range(0, numOfConnections):
        c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        d = c.connectAnonymously(base, serviceLocationOverrides)

        d.addCallback(_search, base, connection, numOfSearches)
        d.addErrback(error)
        l.append(d)
    dl = defer.DeferredList(l)
    dl.addBoth(lambda dummy: reactor.stop())
    reactor.run()
    sys.exit(exitStatus)


if __name__ == "__main__":
    base = "dc=example,dc=com"
    main(
        base=distinguishedname.DistinguishedName(base),
        serviceLocationOverrides={base: ("localhost", None)},
        numOfConnections=5,
        numOfSearches=10,
    )
