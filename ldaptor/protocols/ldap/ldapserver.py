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

from ldaptor import interfaces
from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldaperrors, distinguishedname, ldaperrors

from ldaptor.mutablestring import MutableString
from twisted.python import log
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
	    if o is None:
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

    def handle_LDAPBindRequest(self, request, reply):
        if request.version != 3:
            msg = pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPProtocolError.resultCode,
                                            errorMessage='Version %u not supported' % request.version)
        elif request.dn == '':
            # anonymous bind
            self.boundUser=None
            msg = pureldap.LDAPBindResponse(resultCode=0)
        else:
            msg = pureldap.LDAPBindResponse(resultCode=ldaperrors.LDAPInvalidCredentials.resultCode,
                                            errorMessage='Authentication not yet supported (TODO)')
        return defer.succeed(msg)

    def handle_LDAPUnbindRequest(self, request, reply):
        self.transport.loseConnection()

    def handleUnknown(self, request):
        log.msg('Unknown request: %r' % request)
	msg = pureldap.LDAPExtendedResponse(resultCode=ldaperrors.LDAPProtocolError.resultCode,
                                                 responseName='1.3.6.1.4.1.1466.20036',
                                                 errorMessage='Unknown request.')
	return defer.succeed(msg)

    def _cbHandle(self, response, id):
        self.queue(id, response)

    def _cbLDAPError(self, reason, id):
        reason.trap(ldaperrors.LDAPException)
        self._cbHandle(
            pureldap.LDAPExtendedResponse(resultCode=reason.value.resultCode,
                                          responseName='1.3.6.1.4.1.1466.20036',
                                          errorMessage=reason.value.message),
            id=id)

    def _cbOtherError(self, reason, id):
        self._cbHandle(
            pureldap.LDAPExtendedResponse(resultCode=ldaperrors.LDAPProtocolError.resultCode,
                                          responseName='1.3.6.1.4.1.1466.20036',
                                          errorMessage=reason.getErrorMessage()),
            id=id)

    def handle(self, msg):
	assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
	log.msg('<- %s' % repr(msg))

	if msg.id==0:
	    self.unsolicitedNotification(msg.value)
	else:
            name = msg.value.__class__.__name__
            handler = getattr(self, 'handle_'+name, self.handleUnknown)
            d = handler(msg.value,
                        lambda response: self._cbHandle(response, msg.id))
            if d:
                assert isinstance(d, defer.Deferred)
                d.addCallback(self._cbHandle, msg.id)
                d.addErrback(self._cbLDAPError, msg.id)
                d.addErrback(defer.logError)
                d.addErrback(self._cbOtherError, msg.id)

    def _cbSearchGotBase(self, base, dn, request, reply):
        def _sendEntryToClient(entry):
            reply(pureldap.LDAPSearchResultEntry(
                objectName=str(entry.dn),
                attributes=entry.items(),
                ))
        d = base.search(filterObject=request.filter,
                        attributes=request.attributes,
                        scope=request.scope,
                        derefAliases=request.derefAliases,
                        sizeLimit=request.sizeLimit,
                        timeLimit=request.timeLimit,
                        typesOnly=request.typesOnly,
                        callback=_sendEntryToClient)

        def _done(_):
            return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)
        d.addCallback(_done)
        return d

    def _cbSearchLDAPError(self, reason):
        reason.trap(ldaperrors.LDAPException)
        return pureldap.LDAPSearchResultDone(resultCode=reason.value.resultCode)

    def _cbSearchOtherError(self, reason):
        return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.other)

    def handle_LDAPSearchRequest(self, request, reply):
        dn = distinguishedname.DistinguishedName(request.baseObject)
        root = interfaces.IConnectedLDAPEntry(self.factory)
        d = root.lookup(dn)
        d.addCallback(self._cbSearchGotBase, dn, request, reply)
        d.addErrback(self._cbSearchLDAPError)
        d.addErrback(defer.logError)
        d.addErrback(self._cbSearchOtherError)
        return d

if __name__ == '__main__':
    """
    Demonstration LDAP server; reads LDIF from stdin and
    serves that over LDAP on port 10389.
    """
    from twisted.internet import reactor
    import sys
    log.startLogging(sys.stderr)

    from twisted.python import components
    from twisted.trial import util
    from ldaptor import inmemory

    d = inmemory.fromLDIFFile(sys.stdin)
    db = util.deferredResult(d)

    class LDAPServerFactory(protocol.ServerFactory):
        def __init__(self, root):
            self.root = root

    components.registerAdapter(lambda x: x.root,
                               LDAPServerFactory,
                               interfaces.IConnectedLDAPEntry)

    factory = LDAPServerFactory(db)
    factory.protocol = LDAPServer
    reactor.listenTCP(10389, factory)
    reactor.run()
