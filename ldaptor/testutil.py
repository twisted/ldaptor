"""Utilities for writing Twistedy unit tests and debugging."""

from twisted.internet import reactor
from twisted.test import proto_helpers

def calltrace():
    """Print out all function calls. For debug use only."""
    def printfuncnames(frame, event, arg):
        print "|%s: %s:%d:%s" % (event,
                                 frame.f_code.co_filename,
                                 frame.f_code.co_firstlineno,
                                 frame.f_code.co_name)
    import sys
    sys.setprofile(printfuncnames)

class FakeTransport:
    def __init__(self, proto):
        self.proto = proto

    def loseConnection(self):
        self.proto.connectionLost()

class LDAPClientTestDriver:
    """

    A test driver that looks somewhat like a real LDAPClient.

    Pass in a list of lists of LDAPProtocolResponses. For each sent
    LDAP message, the first item of said list is iterated through, and
    all the items are sent as responses to the callback. The sent LDAP
    messages are stored in self.sent, so you can assert that the sent
    messages are what they are supposed to be.

    """
    def __init__(self, *responses):
        self.sent=[]
        self.responses=list(responses)
        self.connected = None
        self.transport = FakeTransport(self)
    def queue(self, x, callback=None, *args, **kwargs):
        self.sent.append(x)
        assert self.responses, 'Ran out of responses at %r' % x
        responses = self.responses.pop(0)
        if callback is None:
            assert not args
            assert not kwargs
            assert not responses
        else:
            while responses:
                r = responses.pop(0)
                ret = callback(r, *args, **kwargs)
                if responses:
                    assert not ret, \
                           "got %d responses still to give, but handler wants none (got %r)." % (len(responses), ret)
                else:
                    assert ret, \
                           "no more responses to give, but handler still wants more (got %r)." % ret

    def assertNothingSent(self):
        # just a bit more explicit
        self.assertSent()

    def assertSent(self, *shouldBeSent):
        shouldBeSent = list(shouldBeSent)
        assert self.sent == shouldBeSent, \
               '%s expected to send %r but sent %r' % (
            self.__class__.__name__,
            shouldBeSent,
            self.sent)
        sentStr = ''.join([str(x) for x in self.sent])
	shouldBeSentStr = ''.join([str(x) for x in shouldBeSent])
	assert sentStr == shouldBeSentStr, \
               '%s expected to send data %r but sent %r' % (
            self.__class__.__name__,
            shouldBeSentStr,
            sentStr)

    def connectionMade(self):
        """TCP connection has opened"""
        self.connected = 1

    def connectionLost(self, reason=None):
        """Called when TCP connection has been lost"""
        assert not self.responses
        self.connected = 0

    def unbind(self):
        assert self.connected
        r='fake-unbind-by-LDAPClientTestDriver'
        self.queue(r)
        self.transport.loseConnection()

def createServer(proto, *responses):
    def createClient(factory):
        factory.doStart()
        #TODO factory.startedConnecting(c)
        proto = factory.buildProtocol(addr=None)
        proto.connectionMade()
    overrides = {
        '': createClient,
        }
    server = proto(overrides)
    server.protocol = lambda : LDAPClientTestDriver(*responses)
    server.transport = proto_helpers.StringTransport()
    server.connectionMade()
    return server
