from ldaptor.protocols.ldap import proxy
from ldaptor.protocols.ldap import ldapsyntax, ldaperrors
from ldaptor.protocols import pureldap
from ldaptor.entry import sshaDigest
import base64

class ServiceBindingProxy(proxy.Proxy):
    """
    An LDAP proxy that handles non-anonymous bind requests specially.

    BindRequests are intercepted and authentication is attempted
    against each configured service. This authentication is performed
    against the LDAP attribute 'servicePassword', which has the format

    <servicename> <passphrase-digest>

    where <passphrase-digest> looks like the contens of the normal
    'userPassword' attribute.

    Finally, if the authentication does not succeed against any of the
    configured services, the proxy can fallback to passing the bind
    request to the real server.
    """

    services = []

    fallback = False

    def __init__(self,
                 services=None,
                 fallback=None,
                 *a,
                 **kw):
        """
        Initialize the object.

        @param services: List of service names to try to bind against.

        @param fallback: If none of the attempts to authenticate
        against a specific service succeeded, whether to fall back to
        the normal LDAP bind mechanism.
        """

        proxy.Proxy.__init__(self, *a, **kw)
        if services is not None:
            self.services = list(services)
        if fallback is not None:
            self.fallback = fallback

    def _doFetch(self, request, controls, reply):
        e = ldapsyntax.LDAPEntryWithClient(client=self.client,
                                           dn=request.dn)
        d = e.fetch('servicePassword')

        def _noEntry(fail):
            fail.trap(ldaperrors.LDAPNoSuchObject)
            return None
        d.addErrback(_noEntry)
        d.addCallback(self._gotEntry, request, controls, reply)
        return d

    fail_LDAPBindRequest = pureldap.LDAPBindResponse

    def handle_LDAPBindRequest(self, request, controls, reply):
        if request.version != 3:
            raise ldaperrors.LDAPProtocolError, \
                  'Version %u not supported' % request.version

        self.checkControls(controls)

        if request.dn == '':
            # anonymous bind
            return self.handleUnknown(request, controls, reply)
        else:
            d = self._whenConnected(self._doFetch,
                                    request, controls, reply)
            return d

    def _gotEntry(self, e, request, controls, reply):
        if e is not None:
            for service in self.services:
                for svcPasswd in e.get('servicePassword', []):
                    if ' ' not in svcPasswd:
                        # invalid entry that would raise at the split
                        # below if we tried to process it
                        continue
                    name, digest = svcPasswd.split(None, 1)
                    if name == service:
                        # TODO refactor to share the code below
                        if digest.startswith('{SSHA}'):
                            raw = base64.decodestring(digest[len('{SSHA}'):])
                            salt = raw[20:]
                            got = sshaDigest(request.auth, salt)
                            if got == digest:
                                msg = pureldap.LDAPBindResponse(
                                    resultCode=ldaperrors.Success.resultCode,
                                    matchedDN=str(e.dn))
                                return msg

        if self.fallback:
            self.handleUnknown(request, controls, reply)
        else:
            msg = pureldap.LDAPBindResponse(
                resultCode=ldaperrors.LDAPInvalidCredentials.resultCode)
            return msg

if __name__ == '__main__':
    """
    Demonstration LDAP proxy; passes all requests to localhost:389.
    """
    from twisted.internet import reactor, protocol
    from twisted.python import log
    import sys
    log.startLogging(sys.stderr)

    factory = protocol.ServerFactory()
    factory.protocol = lambda : ServiceBindingProxy(overrides={
        '': ('localhost', 389),
        },
                                                    services=[
        'svc1',
        'svc2',
        'svc3',
        ],
                                                    fallback=True,
                                                    )
    reactor.listenTCP(10389, factory)
    reactor.run()
