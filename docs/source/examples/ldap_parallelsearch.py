#!/usr/bin/env python3
# Copyright (C) 2001 Tommi Virtanen
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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
