# Ldaptor, a Pure-Python library for LDAP
# Copyright (C) 2003 Tommi Virtanen
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

"""LDAP protocol server"""

from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldaperrors

from ldaptor.mutablestring import MutableString
from twisted.python import log
from twisted.python.failure import Failure
from twisted.internet import protocol, defer

class LDAPServerConnectionLostException(ldaperrors.LDAPException):
    pass

class LDAPServer(protocol.Protocol):
    """An LDAP server"""

    boundUser = None

    def __init__(self):
	self.buffer = MutableString()
	self.connected = None

    berdecoder = pureldap.LDAPBERDecoderContext_LDAPMessage(
	inherit=pureldap.LDAPBERDecoderContext(
	fallback=pureber.BERDecoderContext()))

    def dataReceived(self, recd):
	self.buffer.append(recd)
	while 1:
	    try:
		o=pureber.ber2object(self.berdecoder, self.buffer)
	    except pureldap.BERExceptionInsufficientData:
		o=None
	    if not o:
		break
	    self.handle(o)

    def connectionMade(self):
	"""TCP connection has opened"""
	self.connected = 1

    def connectionLost(self, reason):
	"""Called when TCP connection has been lost"""
	self.connected = 0

    def queue(self, id, op):
	if not self.connected:
	    raise LDAPServerConnectionLostException()
	msg=pureldap.LDAPMessage(op, id=id)
	log.msg('-> %s' % repr(msg))
	self.transport.write(str(msg))

    def unsolicitedNotification(self, msg):
	log.msg("Got unsolicited notification: %s" % repr(msg))

    def handle_LDAPBindRequest(self, request):
        if request.version != 3:
            msg = pureldap.LDAPBindResponse(resultCode=ldaperrors.errors['protocolError'],
                                            errorMessage='Version %u not supported' % request.version)
        elif request.dn == '':
            # anonymous bind
            self.boundUser=None
            msg = pureldap.LDAPBindResponse(resultCode=0)
        else:
            msg = pureldap.LDAPBindResponse(resultCode=ldaperrors.errors['invalidCredentials'],
                                            errorMessage='Authentication not yet supported (TODO)')
        return defer.succeed(msg)

    def handle_LDAPUnbindRequest(self, request):
        self.transport.loseConnection()

    def handleUnknown(self, request):
        log.msg('Unknown request: %r' % request)
        self.queue(0,
                   pureldap.LDAPExtendedResponse(resultCode=ldaperrors.errors['protocolError'],
                                                 responseName='1.3.6.1.4.1.1466.20036',
                                                 errorMessage='Unknown request.'))
        self.transport.loseConnection()

    def _cbHandle(self, response, id):
        self.queue(id, response)

    def handle(self, msg):
	assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
	log.msg('<- %s' % repr(msg))

	if msg.id==0:
	    self.unsolicitedNotification(msg.value)
	else:
            name = msg.value.__class__.__name__
            handler = getattr(self, 'handle_'+name, self.handleUnknown)
            d = handler(msg.value)
            if d:
                assert isinstance(d, defer.Deferred)
                d.addCallback(self._cbHandle, msg.id)

if __name__ == '__main__':
    from twisted.internet import reactor
    import sys
    log.startLogging(sys.stderr)

    class TestLDAPServer(LDAPServer):
        def handle_LDAPSearchRequest(self, request):
            msg = pureldap.LDAPSearchResultDone(resultCode=0)
            return defer.succeed(msg)
    
    factory = protocol.ServerFactory()
    factory.protocol = TestLDAPServer
    reactor.listenTCP(10389, factory)
    reactor.run()
