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

from twisted.python import log
from twisted.internet import protocol, defer

class LDAPServerConnectionLostException(ldaperrors.LDAPException):
    pass

class BaseLDAPServer(protocol.Protocol):
    debug = False

    def __init__(self):
	self.buffer = ''
	self.connected = None

    berdecoder = pureldap.LDAPBERDecoderContext_TopLevel(
        inherit=pureldap.LDAPBERDecoderContext_LDAPMessage(
        fallback=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext()),
        inherit=pureldap.LDAPBERDecoderContext(fallback=pureber.BERDecoderContext())))

    def dataReceived(self, recd):
	self.buffer += recd
	while 1:
	    try:
		o, bytes=pureber.berDecodeObject(self.berdecoder, self.buffer)
	    except pureldap.BERExceptionInsufficientData:
		o, bytes=None, 0
            self.buffer = self.buffer[bytes:]
	    if o is None:
		break
	    self.handle(o)

    def connectionMade(self):
	"""TCP connection has opened"""
	self.connected = 1

    def connectionLost(self, reason=protocol.connectionDone):
	"""Called when TCP connection has been lost"""
	self.connected = 0

    def queue(self, id, op):
	if not self.connected:
	    raise LDAPServerConnectionLostException()
	msg=pureldap.LDAPMessage(op, id=id)
        if self.debug:
            log.debug('S->C %s' % repr(msg))
	self.transport.write(str(msg))

    def unsolicitedNotification(self, msg):
	log.msg("Got unsolicited notification: %s" % repr(msg))

    def checkControls(self, controls):
        if controls is not None:
            for controlType, criticality, controlValue in controls:
                if criticality:
                    raise ldaperrors.LDAPUnavailableCriticalExtension, \
                          'Unknown control %s' % controlType

    def handleUnknown(self, request, controls, callback):
        log.msg('Unknown request: %r' % request)
	msg = pureldap.LDAPExtendedResponse(resultCode=ldaperrors.LDAPProtocolError.resultCode,
                                            responseName='1.3.6.1.4.1.1466.20036',
                                            errorMessage='Unknown request')
	return msg

    def _cbLDAPError(self, reason, name):
        reason.trap(ldaperrors.LDAPException)
        return self._callErrorHandler(name=name,
                                      resultCode=reason.value.resultCode,
                                      errorMessage=reason.value.message)

    def _cbHandle(self, response, id):
        if response is not None:
            self.queue(id, response)

    def failDefault(self, resultCode, errorMessage):
        return pureldap.LDAPExtendedResponse(resultCode=resultCode,
                                             responseName='1.3.6.1.4.1.1466.20036',
                                             errorMessage=errorMessage)

    def _callErrorHandler(self, name, resultCode, errorMessage):
        errh = getattr(self, 'fail_'+name, self.failDefault)
        return errh(resultCode=resultCode, errorMessage=errorMessage)

    def _cbOtherError(self, reason, name):
        return self._callErrorHandler(name=name,
                                      resultCode=ldaperrors.LDAPProtocolError.resultCode,
                                      errorMessage=reason.getErrorMessage())

    def handle(self, msg):
	assert isinstance(msg.value, pureldap.LDAPProtocolRequest)
        if self.debug:
            log.debug('S<-C %s' % repr(msg))

	if msg.id==0:
	    self.unsolicitedNotification(msg.value)
	else:
            name = msg.value.__class__.__name__
            handler = getattr(self, 'handle_'+name, self.handleUnknown)
            d = defer.maybeDeferred(handler,
                                    msg.value,
                                    msg.controls,
                                    lambda response: self._cbHandle(response, msg.id))
            assert isinstance(d, defer.Deferred)
            d.addErrback(self._cbLDAPError, name)
            d.addErrback(defer.logError)
            d.addErrback(self._cbOtherError, name)
            d.addCallback(self._cbHandle, msg.id)


class LDAPServer(BaseLDAPServer):
    """An LDAP server"""
    boundUser = None

    fail_LDAPBindRequest = pureldap.LDAPBindResponse

    def handle_LDAPBindRequest(self, request, controls, reply):
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError, \
                  'Version %u not supported' % request.version

        self.checkControls(controls)

        if request.dn == '':
            # anonymous bind
            self.boundUser=None
            return pureldap.LDAPBindResponse(resultCode=0)
        else:
            dn = distinguishedname.DistinguishedName(request.dn)
            root = interfaces.IConnectedLDAPEntry(self.factory)
            d = root.lookup(dn)

            def _noEntry(fail):
                fail.trap(ldaperrors.LDAPNoSuchObject)
                return None
            d.addErrback(_noEntry)

            def _gotEntry(entry, auth):
                if entry is None:
                    raise ldaperrors.LDAPInvalidCredentials

                d = entry.bind(auth)
                def _cb(entry):
                    msg = pureldap.LDAPBindResponse(
                        resultCode=ldaperrors.Success.resultCode,
                        matchedDN=str(entry.dn))
                    return msg
                d.addCallback(_cb)
                return d
            d.addCallback(_gotEntry, request.auth)

            return d

    def handle_LDAPUnbindRequest(self, request, controls, reply):
        # explicitly do not check unsupported critical controls -- we
        # have no way to return an error, anyway.
        self.transport.loseConnection()

    def getRootDSE(self, request, reply):
        root = interfaces.IConnectedLDAPEntry(self.factory)
        reply(pureldap.LDAPSearchResultEntry(
            objectName='',
            attributes=[ ('supportedLDAPVersion', ['3']),
                         ('namingContexts', [str(root.dn)]),
                         ('supportedExtension', [
            pureldap.LDAPPasswordModifyRequest.oid.value,
            ]),
                         ],
            ))
        return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)

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
        return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.other,
                                             errorMessage=reason.getErrorMessage())

    fail_LDAPSearchRequest = pureldap.LDAPSearchResultDone

    def handle_LDAPSearchRequest(self, request, controls, reply):
        self.checkControls(controls)

        if (request.baseObject == ''
            and request.scope == pureldap.LDAP_SCOPE_baseObject
            and request.filter == pureldap.LDAPFilter_present('objectClass')):
            return self.getRootDSE(request, reply)
        dn = distinguishedname.DistinguishedName(request.baseObject)
        root = interfaces.IConnectedLDAPEntry(self.factory)
        d = root.lookup(dn)
        d.addCallback(self._cbSearchGotBase, dn, request, reply)
        d.addErrback(self._cbSearchLDAPError)
        d.addErrback(defer.logError)
        d.addErrback(self._cbSearchOtherError)
        return d

    fail_LDAPDelRequest = pureldap.LDAPDelResponse

    def handle_LDAPDelRequest(self, request, controls, reply):
        self.checkControls(controls)

        dn = distinguishedname.DistinguishedName(request.value)
        root = interfaces.IConnectedLDAPEntry(self.factory)
        d = root.lookup(dn)
        def _gotEntry(entry):
            d = entry.delete()
            return d
        d.addCallback(_gotEntry)
        def _report(entry):
            return pureldap.LDAPDelResponse(resultCode=0)
        d.addCallback(_report)
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
