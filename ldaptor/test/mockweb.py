"""I mock the web."""

from StringIO import StringIO

from nevow import appserver, url
from twisted.internet import address, protocol, error
from twisted.protocols import http
from twisted.web import client

from nevow import testutil
from ldaptor.test import util

class FakeChannel(testutil.FakeChannel):
    def requestDone(self, request):
        self.transport.loseConnection()

class MyHTTPClient(http.HTTPClient):
    status = None
    headers = None
    response = None

    def handleStatus(self, version, status, message):
        self.status = (version, status, message)

    def handleHeader(self, key, val):
        if self.headers is None:
            self.headers = {}
        if key not in self.headers:
            self.headers[key] = []
        self.headers[key].append(val)

    def handleResponse(self, data):
        self.response = data

    def __repr__(self):
        return '<%s status=%r headers=%r response=%r>' % (
            self.__class__.__name__,
            self.status,
            self.headers,
            self.response)

class MyHTTPPageGetter(client.HTTPPageGetter):
    def handleStatus_301(self):
        if not self.followRedirect:
            client.HTTPPageGetter.handleStatus_301(self)
            return

        l = self.headers.get('location')
        if not l:
            self.handleStatusDefault()
        url = l[0]
        self.factory.setURL(url)

        _getPage_connect(clientFactory=self.factory,
                         serverAddress=address.IPv4Address(
            'TCP', self.factory.host, self.factory.port),
                         clientAddress=None)
        self.quietLoss = 1
        self.transport.loseConnection()

class HTTPClientFactory_noCookies(client.HTTPClientFactory):
    def gotHeaders(self, headers):
        client.HTTPClientFactory.gotHeaders(self, headers)
        self.cookies.clear()

def _getPage_connect(clientFactory,
                     serverAddress,
                     clientAddress):
    clientProto = clientFactory.buildProtocol(serverAddress)
    serverProto = clientFactory.site.buildProtocol(clientAddress)
    pump = util.returnConnected(serverProto, clientProto,
                                serverAddress=serverAddress,
                                clientAddress=clientAddress)

def getPage(site, u, extraInfo=False,
            factoryClass=client.HTTPClientFactory,
            *a, **kw):
    u = url.URL.fromString(str(u))
    clientFactory = factoryClass(str(u), *a, **kw)
    clientFactory.protocol = MyHTTPPageGetter
    clientFactory.site = site
    if ':' in u.netloc:
        host, port = u.netloc.split(':', 1)
    else:
        host, port = u.netloc, 80
    serverAddress = address.IPv4Address('TCP', host, port)
    clientAddress = address.IPv4Address('TCP', 'localhost', 1024)
    _getPage_connect(clientFactory, serverAddress, clientAddress)

    if extraInfo:
        def _cb(page):
            return {'status': clientFactory.status,
                    'version': clientFactory.version,
                    'message': clientFactory.message,
                    'headers': clientFactory.headers,
                    'page': page,
                    'url': url.URL.fromString(clientFactory.url),
                    }
        clientFactory.deferred.addCallback(_cb)
    return clientFactory.deferred

def getPage_noCookies(*a, **kw):
    defaults = {
        'factoryClass': HTTPClientFactory_noCookies,
        }
    defaults.update(kw)
    return getPage(*a, **defaults)
