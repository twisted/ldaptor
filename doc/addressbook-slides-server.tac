# -*- python -*-
# run me with "twistd -noy addressbook-slides-server.tac"
from twisted.application import service, internet
from twisted.web import server, resource, static
from twisted.internet import protocol, reactor
from cStringIO import StringIO
import re

class StartMeld(resource.Resource):
    isLeaf = True
    safeRe = re.compile('^\d\d_[a-z]+')

    def render(self, request):
        request.setHeader('content-type', 'text/plain')
        if len(request.postpath) != 2:
            return 'Usage: /diff/FROM/TO\n'

        from_, to = request.postpath

        if not self.safeRe.match(from_):
            return 'Path element "from" is invalid.\n'
        if not self.safeRe.match(to):
            return 'Path element "to" is invalid.\n'

        proto = protocol.ProcessProtocol()
        reactor.spawnProcess(proto,
                             'meld',
                             ['meld',
                              'examples/addressbook/%s' % from_,
                              'examples/addressbook/%s' % to],
                             env=None)
        return 'Launched comparison of %s and %s.\n' % (from_, to)

application = service.Application("addressbook-slides")
resource = static.File('addressbook-slides')
resource.putChild('diff', StartMeld())
site = server.Site(resource)
webServer = internet.TCPServer(8087, site)
webServer.setServiceParent(application)
