import sys

from twisted.internet import defer
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.internet.task import react
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapsyntax import LDAPEntry


@defer.inlineCallbacks
def onConnect(client):
    # The following arguments may be also specified as unicode strings
    # but it is recommended to use byte strings for ldaptor objects
    basedn = b'dc=example,dc=org'
    binddn = b'cn=bob,ou=people,dc=example,dc=org'
    bindpw = b'secret'
    query = b'(cn=bob)'
    try:
        yield client.bind(binddn, bindpw)
    except Exception as ex:
        print(ex)
        raise
    o = LDAPEntry(client, basedn)
    results = yield o.search(filterText=query)
    for entry in results:
        print(entry.getLDIF())


def onError(err):
    err.printDetailedTraceback(file=sys.stderr)


def main(reactor):
    endpoint_str = "tcp:host=127.0.0.1:port=8080"
    e = clientFromString(reactor, endpoint_str)
    d = connectProtocol(e, LDAPClient())
    d.addCallback(onConnect)
    d.addErrback(onError)
    return d


react(main)
