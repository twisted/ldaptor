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

"""LDAP protocol client"""

from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldaperrors

from twisted.python import log
from twisted.python.failure import Failure
from twisted.internet import protocol, defer, ssl, reactor

class LDAPClientConnectionLostException(ldaperrors.LDAPException):
    def __str__(self):
        return 'Connection lost'

class LDAPStartTLSBusyError(ldaperrors.LDAPOperationsError):
    def __init__(self, onwire, message=None):
        self.onwire = onwire
        ldaperrors.LDAPOperationsError.__init__(self, message=message)

    def __str__(self):
        return 'Cannot STARTTLS while operations on wire: %r' % self.onwire

class LDAPClient(protocol.Protocol):
    """An LDAP client"""
    debug = False

    def __init__(self):
	self.onwire = {}
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
		o, bytes = pureber.berDecodeObject(self.berdecoder, self.buffer)
	    except pureldap.BERExceptionInsufficientData:
		o, bytes = None, 0
            self.buffer = self.buffer[bytes:]
	    if not o:
		break
	    self.handle(o)

    def connectionMade(self):
	"""TCP connection has opened"""
	self.connected = 1

    def connectionLost(self, reason=protocol.connectionDone):
	"""Called when TCP connection has been lost"""
	self.connected = 0

    def queue(self, op, handler=None, *args, **kwargs):
	if not self.connected:
	    raise LDAPClientConnectionLostException()
	msg=pureldap.LDAPMessage(op)
        if self.debug:
            log.debug('C->S %s' % repr(msg))
	assert not self.onwire.has_key(msg.id)
	assert op.needs_answer or handler is None
        assert ((args==()
                 and kwargs=={})
                or handler is not None)
	if op.needs_answer:
	    self.onwire[msg.id]=(handler, args, kwargs)
	self.transport.write(str(msg))

    def unsolicitedNotification(self, msg):
	log.msg("Got unsolicited notification: %s" % repr(msg))

    def handle(self, msg):
	assert isinstance(msg.value, pureldap.LDAPProtocolResponse)
        if self.debug:
            log.debug('C<-S %s' % repr(msg))

	if msg.id==0:
	    self.unsolicitedNotification(msg.value)
	else:
	    handler, args, kwargs = self.onwire[msg.id]

	    # Return true to mark request as fully handled
	    if handler is None or handler(msg.value, *args, **kwargs):
		del self.onwire[msg.id]


    ##Bind
    def bind(self, dn='', auth=''):
	d=defer.Deferred()
	if not self.connected:
	    d.errback(Failure(
		LDAPClientConnectionLostException()))
	else:
	    r=pureldap.LDAPBindRequest(dn=dn, auth=auth)
	    self.queue(r, self._handle_bind_msg, d)
	return d

    def _handle_bind_msg(self, resp, d):
	assert isinstance(resp, pureldap.LDAPBindResponse)
	assert resp.referral is None #TODO
	if resp.resultCode==0:
	    d.callback((resp.matchedDN, resp.serverSaslCreds))
	else:
	    d.errback(Failure(
		ldaperrors.get(resp.resultCode, resp.errorMessage)))
        return True

    ##Unbind
    def unbind(self):
	if not self.connected:
	    raise "Not connected (TODO)" #TODO make this a real object
	r=pureldap.LDAPUnbindRequest()
	self.queue(r)
	self.transport.loseConnection()

    def _cbStartTLS(self, msg, ctx, d):
	assert isinstance(msg, pureldap.LDAPExtendedResponse)
	assert msg.referral is None #TODO
	if msg.resultCode==ldaperrors.Success.resultCode:
            self.transport.startTLS(ctx)
	    d.callback(self)
	else:
            d.errback(ldaperrors.get(msg.resultCode, msg.errorMessage))
        return True

    def startTLS(self, ctx=None):
        """
        Start Transport Layer Security.

        It is the callers responsibility to make sure other things
        are not happening at the same time.

        @todo: server hostname check, see rfc2830 section 3.6.

        """
        if ctx is None:
            ctx = ssl.ClientContextFactory()
        # we always delay by one event loop iteration to make
        # sure the previous handler has exited and self.onwire
        # has been cleaned up
	d=defer.Deferred()
        d.addCallback(self._startTLS)
        reactor.callLater(0, d.callback, ctx)
        return d

    def _startTLS(self, ctx):
	if not self.connected:
            raise LDAPClientConnectionLostException
        elif self.onwire:
            raise LDAPStartTLSBusyError, self.onwire
        else:
	    op=pureldap.LDAPStartTLSRequest()
            d=defer.Deferred()
	    self.queue(op, self._cbStartTLS, ctx, d)
            return d
        

class LDAPOperation:
    def __init__(self, client):
	self.client=client

class LDAPSearch(LDAPOperation):
    def __init__(self,
		 deferred,
		 client,
		 baseObject='',
		 scope=pureldap.LDAP_SCOPE_wholeSubtree,
		 derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
		 sizeLimit=0,
		 timeLimit=0,
		 typesOnly=0,
		 filter=pureldap.LDAPFilterMatchAll,
		 attributes=[],
		 ):
	LDAPOperation.__init__(self, client)
	self.deferred=deferred
	r=pureldap.LDAPSearchRequest(baseObject=str(baseObject),
				     scope=scope,
				     derefAliases=derefAliases,
				     sizeLimit=sizeLimit,
				     timeLimit=timeLimit,
				     typesOnly=typesOnly,
				     filter=filter,
				     attributes=attributes)
	self.client.queue(r, self.handle_msg)

    def handle_msg(self, msg):
	if isinstance(msg, pureldap.LDAPSearchResultDone):
	    assert msg.referral is None #TODO
	    if msg.resultCode==0: #TODO ldap.errors.success
		assert msg.matchedDN==''
		self.deferred.callback(self)
	    else:
		try:
		    raise ldaperrors.get(msg.resultCode, msg.errorMessage)
		except:
		    self.deferred.errback(Failure())
	    return 1
	else:
	    assert isinstance(msg, pureldap.LDAPSearchResultEntry)
	    self.handle_entry(msg.objectName, msg.attributes)
	    return 0

    def handle_entry(self, objectName, attributes):
	pass
