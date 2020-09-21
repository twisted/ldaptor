import functools
from io import BytesIO

from twisted.python import failure
from twisted.internet import reactor, protocol, defer
from twisted.test import testutils


class FakeTransport(protocol.FileWrapper):
    disconnecting = False
    disconnect_done = False

    def __init__(self):
        self.data = BytesIO()
        protocol.FileWrapper.__init__(self, self.data)


class FasterIOPump(testutils.IOPump):
    def pump(self):
        """Move data back and forth.

        Returns whether any data was moved.
        """
        self.clientIO.seek(0)
        self.serverIO.seek(0)
        cData = self.clientIO.read()
        sData = self.serverIO.read()
        self.clientIO.seek(0)
        self.serverIO.seek(0)
        self.clientIO.truncate()
        self.serverIO.truncate()
        self.server.dataReceived(cData)
        self.client.dataReceived(sData)
        if cData or sData:
            return 1
        else:
            return 0


class IOPump(FasterIOPump):
    active = []

    def __init__(self,
                 client, server,
                 clientTransport, serverTransport):
        self.clientTransport = clientTransport
        self.serverTransport = serverTransport
        testutils.IOPump.__init__(self,
                                  client=client,
                                  server=server,
                                  clientIO=clientTransport.data,
                                  serverIO=serverTransport.data)
        self.active.append(self)


def returnConnected(server, client):
    """Take two Protocol instances and connect them.
    """
    clientTransport = FakeTransport()
    client.makeConnection(clientTransport)
    serverTransport = FakeTransport()
    server.makeConnection(serverTransport)
    pump = IOPump(client, server,
                  clientTransport,
                  serverTransport)
    # Challenge-response authentication:
    pump.flush()
    # Uh...
    pump.flush()
    return pump


def _getDeferredResult(d):
    resultSet = []
    d.addBoth(resultSet.append)
    while not resultSet:
        for pump in IOPump.active:
            pump.pump()
        reactor.iterate()
    return resultSet[0]


def pumpingDeferredResult(d):
    result = _getDeferredResult(d)
    return (
        result.raiseException()
        if isinstance(result, failure.Failure)
        else result
    )


def fromCoroutineFunction(corofn):
    @functools.wraps(corofn)
    def wrapper(*args, **kwargs):
        return defer.ensureDeferred(corofn(*args, **kwargs))

    return wrapper
