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

from ldaptor.mutablestring import MutableString
from twisted.python import log
from twisted.python.failure import Failure
from twisted.internet import protocol, defer

class LDAPClientConnectionLostException(ldaperrors.LDAPException):
    pass

class LDAPClient(protocol.Protocol):
    """An LDAP client"""

    def __init__(self):
	self.onwire = {}
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

    def queue(self, op, handler=None):
	if not self.connected:
	    raise LDAPClientConnectionLostException()
	msg=pureldap.LDAPMessage(op)
	#log.msg('-> %s' % repr(msg))
	assert not self.onwire.has_key(msg.id)
	assert op.needs_answer or not handler
	if op.needs_answer:
	    self.onwire[msg.id]=handler
	self.transport.write(str(msg))

    def unsolicitedNotification(self, msg):
	log.msg("Got unsolicited notification: %s" % repr(msg))

    def handle(self, msg):
	assert isinstance(msg.value, pureldap.LDAPProtocolResponse)
	#log.msg('<- %s' % repr(msg))

	if msg.id==0:
	    self.unsolicitedNotification(msg.value)
	else:
	    handler = self.onwire[msg.id]

	    # Return true to mark request as fully handled
	    if handler==None or handler(msg.value):
		del self.onwire[msg.id]


    ##Bind
    def bind(self, dn='', auth=''):
	d=defer.Deferred()
	if not self.connected:
	    d.errback(Failure(
		LDAPClientConnectionLostException()))
	else:
	    r=pureldap.LDAPBindRequest(dn=dn, auth=auth)
	    self.queue(r, d.callback) #TODO queue needs info back from callback!!!
	    d.addCallback(self._handle_bind_msg)
	return d

    def _handle_bind_msg(self, resp):
	assert isinstance(resp, pureldap.LDAPBindResponse)
	assert resp.referral==None #TODO
	if resp.resultCode==0:
	    return (resp.matchedDN, resp.serverSaslCreds)
	else:
	    raise Failure(
		ldaperrors.get(resp.resultCode, resp.errorMessage))

    ##Unbind
    def unbind(self):
	if not self.connected:
	    raise "Not connected (TODO)" #TODO make this a real object
	r=pureldap.LDAPUnbindRequest()
	self.queue(r)
	self.transport.loseConnection()

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
	    assert msg.referral==None #TODO
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

class LDAPAddEntry(LDAPOperation):
    def __init__(self,
		 client,
		 object,
		 attributes):
	"""
	Request addition of LDAP entry.

	object is a string representation of the object DN.

	attributes is a list of LDAPAttributeDescription,
	BERSet(LDAPAttributeValue, ..) pairs.

	"""

	LDAPOperation.__init__(self, client)
	r=pureldap.LDAPAddRequest(entry=object,
				  attributes=attributes)
	self.client.queue(r, self.handle_msg)

    def handle_msg(self, msg):
	assert isinstance(msg, pureldap.LDAPAddResponse)
	assert msg.referral==None #TODO
	if msg.resultCode==0: #TODO ldap.errors.success
	    assert msg.matchedDN==''
	    self.handle_success()
	    return 1
	else:
	    self.handle_fail(Failure(
		ldaperrors.get(msg.resultCode, msg.errorMessage)))
	    return 1

    def handle_success(self):
	pass

    def handle_fail(self, fail):
	pass
