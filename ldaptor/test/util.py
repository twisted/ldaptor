from twisted.python import failure
from twisted.internet import reactor, protocol, address, error
from twisted.test import testutils

from StringIO import StringIO

class FakeTransport(protocol.FileWrapper):
    disconnecting = False
    disconnect_done = False
    def __init__(self, addr, peerAddr):
        self.data = StringIO()
        protocol.FileWrapper.__init__(self, self.data)
        self.addr = addr
        self.peerAddr = peerAddr
    def getHost(self):
        return self.addr
    def getPeer(self):
        return self.peerAddr
    def loseConnection(self):
        self.disconnecting = True

class IOPump(testutils.IOPump):
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
    def pump(self):
        testutils.IOPump.pump(self)
        if (self.clientTransport.disconnecting
            and not self.clientTransport.data.getvalue()
            and not self.clientTransport.disconnect_done):
            self.server.connectionLost(error.ConnectionDone)
            self.clientTransport.disconnect_done = True

        if (self.serverTransport.disconnecting
            and not self.serverTransport.data.getvalue()
            and not self.serverTransport.disconnect_done):
            self.client.connectionLost(error.ConnectionDone)
            self.serverTransport.disconnect_done = True
            
        if (self.clientTransport.disconnect_done
            and self.serverTransport.disconnect_done):
            self.active.remove(self)

    def __repr__(self):
        return '<%s client=%r/%r server=%r/%r>' % (
            self.__class__.__name__,
            self.client,
            self.clientIO.getvalue(),
            self.server,
            self.serverIO.getvalue(),

            )
def returnConnected(server, client,
                    clientAddress=None,
                    serverAddress=None):
    """Take two Protocol instances and connect them.
    """
    if serverAddress is None:
        serverAddress = address.IPv4Address('TCP', 'localhost', 1)
    if clientAddress is None:
        clientAddress = address.IPv4Address('TCP', 'localhost', 2)
    clientTransport = FakeTransport(clientAddress, serverAddress)
    client.makeConnection(clientTransport)
    serverTransport = FakeTransport(serverAddress, clientAddress)
    server.makeConnection(serverTransport)
    pump = IOPump(client, server,
                  clientTransport,
                  serverTransport)
    # Challenge-response authentication:
    pump.flush()
    # Uh...
    pump.flush()
    return pump

def _append(result, lst):
    lst.append(result)

def _getDeferredResult(d, timeout=None):
    if timeout is not None:
        d.setTimeout(timeout)
    resultSet = []
    d.addBoth(_append, resultSet)
    while not resultSet:
        for pump in IOPump.active:
            pump.pump()
        reactor.iterate()
    return resultSet[0]

def pumpingDeferredResult(d, timeout=None):
    result = _getDeferredResult(d, timeout)
    if isinstance(result, failure.Failure):
        if result.tb:
            raise result.value.__class__, result.value, result.tb
        raise result.value
    else:
        return result
