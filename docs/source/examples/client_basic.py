#! /usr/bin/env python

import sys

from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry
from twisted.internet.defer import inlineCallbacks
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.internet.task import react
from twisted.python import log


@inlineCallbacks
def onConnect(clientProtocol):
    o = LDAPEntry(clientProtocol, "dc=fr")
    results = yield o.search()
    data = "".join([result.getLDIF() for result in results])
    log.msg(f"LDIF formatted results:\n{data}")


def onError(err, reactor):
    if reactor.running:
        log.err(err)
        reactor.stop()


def main(reactor):
    log.startLogging(sys.stdout)
    endpoint_str = "tcp:host=localhost:port=8080"
    e = clientFromString(reactor, endpoint_str)
    d = connectProtocol(e, LDAPClient())
    d.addCallback(onConnect)
    d.addErrback(onError, reactor)
    return d


react(main)
