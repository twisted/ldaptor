#!/usr/bin/python
# Twisted, the Framework of Your Internet
# Copyright (C) 2001 Matthew W. Lefkowitz
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

from ldaptor.protocols.ldap import ldapclient
from ldaptor.protocols import pureber
from twisted.internet import protocol, defer
from twisted.internet import reactor
import sys

CONNECTIONS=5
SEARCHES=10

class LDAPSearchAndPrint(ldapclient.LDAPSearch):
    def __init__(self, deferred, client, prefix):
	ldapclient.LDAPSearch.__init__(self, deferred, client,
				       baseObject='dc=example, dc=com')
	self.prefix=prefix

    def handle_entry(self, objectName, attributes):
	print "%s: %s %s"%(self.prefix, objectName,
			   repr(map(lambda (a,l):
				    (str(a),
				     map(lambda i: str(i), l)),
				    attributes)))

class SearchALot(ldapclient.LDAPClient):
    factory=None

    def __init__(self):
	ldapclient.LDAPClient.__init__(self)

    def connectionMade(self):
	d=self.bind()
	d.addCallback(self._handle_bind_success)

    def _handle_bind_success(self, x):
	matchedDN, serverSaslCreds = x
	l=[]
	for prefix in [self.factory.prefix+x
		       for x
		       in map(str, range(0,SEARCHES))]:
	    d=defer.Deferred()
	    l.append(d)
	    LDAPSearchAndPrint(d, self, prefix)

	dl=defer.DeferredList(l)
	dl.chainDeferred(self.factory.deferred)

class SearchALotFactory(protocol.ClientFactory):
    protocol = SearchALot
    def __init__(self, deferred, prefix):
	self.deferred=deferred
	self.prefix=prefix

    def clientConnectionFailed(self, connector, reason):
	self.deferred.errback(reason)

exitStatus=0

def error(fail):
    print >>sys.stderr, 'fail:', fail.getErrorMessage()
    global exitStatus
    exitStatus=1

def main():
    l=[]
    for x in xrange(0,CONNECTIONS):
	d=defer.Deferred()
	l.append(d)
	d.addErrback(error)
	s=SearchALotFactory(d, str(x)+'.')
	reactor.connectTCP("localhost", 389, s)
    dl=defer.DeferredList(l)
    dl.addBoth(lambda dummy: reactor.stop())
    reactor.run()
    sys.exit(exitStatus)

if __name__ == "__main__":
    main()
