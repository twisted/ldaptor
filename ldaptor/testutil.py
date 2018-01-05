"""Utilities for writing Twistedy unit tests and debugging."""

from twisted.internet import defer
from twisted.python import failure
from twisted.trial import unittest
from twisted.test import proto_helpers
from ldaptor import config


def mustRaise(dummy):
    raise unittest.FailTest('Should have raised an exception.')


def calltrace():
    """Print out all function calls. For debug use only."""

    def printfuncnames(frame, event, arg):
        print("|%s: %s:%d:%s" %
              (event, frame.f_code.co_filename,
               frame.f_code.co_firstlineno,
               frame.f_code.co_name))

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

    It is also possible to include a Failure instance instead of a list
    of LDAPProtocolResponses which will cause the errback to be called
    with the failure.
    """
    fakeUnbindResponse = 'fake-unbind-by-LDAPClientTestDriver'

    def __init__(self, *responses):
        self.sent = []
        self.responses = list(responses)
        self.connected = None
        self.transport = FakeTransport(self)

    def send(self, op):
        self.sent.append(op)
        l = self._response()
        assert len(l) == 1, "got %d responses for a .send()" % len(l)
        r = l[0]
        if isinstance(r, failure.Failure):
            return defer.fail(r)
        else:
            return defer.succeed(r)

    def send_multiResponse(self, op, handler, *args, **kwargs):
        d = defer.Deferred()
        self.sent.append(op)
        responses = self._response()
        while responses:
            r = responses.pop(0)
            if isinstance(r, failure.Failure):
                d.errback(r)
                break
            ret = handler(r, *args, **kwargs)
            if responses:
                msg = (
                    "got %d responses still to give, "
                    "but handler wants none (got %r).") % (len(responses), ret)
                assert not ret, msg
            else:
                msg = (
                    "no more responses to give, but handler "
                    "still wants more (got %r)." % ret)
                assert ret, msg
        return d

    def send_noResponse(self, op):
        if len(self.responses) == 0:
            msg = "Ran out of responses"
            assert op == self.fakeUnbindResponse, msg
        else:
            self.responses.pop(0)
        self.sent.append(op)

    def _response(self):
        assert self.responses, 'Ran out of responses'
        responses = self.responses.pop(0)
        return responses

    def assertNothingSent(self):
        # just a bit more explicit
        self.assertSent()

    def assertSent(self, *shouldBeSent):
        shouldBeSent = list(shouldBeSent)
        msg = '%s expected to send %r but sent %r' % (
            self.__class__.__name__,
            shouldBeSent,
            self.sent)
        assert self.sent == shouldBeSent, msg
        sentStr = ''.join([str(x) for x in self.sent])
        shouldBeSentStr = ''.join([str(x) for x in shouldBeSent])
        msg = '%s expected to send data %r but sent %r' % (
            self.__class__.__name__,
            shouldBeSentStr,
            sentStr)
        assert sentStr == shouldBeSentStr, msg

    def connectionMade(self):
        """TCP connection has opened"""
        self.connected = 1

    def connectionLost(self, reason=None):
        """
        Called when TCP connection has been lost
        """
        msg = (
            "connectionLost called even when have "
            "responses left: %r" % self.responses)
        assert not self.responses, msg
        self.connected = 0

    def unbind(self):
        assert self.connected
        r = self.fakeUnbindResponse
        self.send_noResponse(r)
        self.transport.loseConnection()


def createServer(proto, *responses, **kw):
    """
    Create an LDAP server for testing.
    :param proto: The server protocol factory (e.g. `ProxyBase`).
    :param responses: The responses to initialize the `LDAPClientTestDrive`.
    :param proto_args: Optional mapping passed as keyword args to protocol factory.
    """
    if 'proto_args' in kw:
        proto_args = kw['proto_args']
        del kw['proto_args']
    else:
        proto_args = {}

    def createClient(factory):
        factory.doStart()
        proto = factory.buildProtocol(addr=None)
        proto.connectionMade()

    overrides = kw.setdefault('serviceLocationOverrides', {})
    overrides.setdefault('', createClient)
    conf = config.LDAPConfig(**kw)
    server = proto(conf, **proto_args)
    clientTestDriver = LDAPClientTestDriver(*responses)
    server.protocol = lambda: clientTestDriver
    server.clientTestDriver = clientTestDriver
    server.transport = proto_helpers.StringTransport()
    server.connectionMade()
    return server
