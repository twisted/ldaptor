"""
An ldaptor LDAP server which can authenticate based on UPN, as AD does.

The LDAP entry needs to have the ``userPrincipalName`` attribute set:

    dn: uid=bob,ou=people,dc=example,dc=org
    objectclass: top
    objectclass: person
    objectClass: inetOrgPerson
    uid: bob
    cn: bobby
    gn: Bob
    sn: Roberts
    mail: bob@example.org
    homeDirectory: e:\\Users\\bob
    userPassword: pass
    userPrincipalName: bob@ad.example.org

A UPN bind arrives as ``User.Name@ad.example.tld`` in the BIND DN slot
rather than a normal distinguished name. This server intercepts the BIND
request, looks up the entry whose ``userPrincipalName`` matches, and
rewrites the request's DN to that entry's real DN before delegating to
the stock :class:`LDAPServer` bind handler. Non-UPN BIND requests are
forwarded unchanged.
"""

from ldaptor import interfaces
from ldaptor.protocols import pureldap
from twisted.internet import defer
from ldaptor.protocols.ldap.ldapserver import LDAPServer


class LDAPServerWithUPNBind(LDAPServer):
    """
    An LDAP server which supports BIND using a UPN (User Principal Name),
    similar to Active Directory.
    """

    _loginAttribute = b"userPrincipalName"

    @defer.inlineCallbacks
    def handle_LDAPBindRequest(self, request, *args, **kwargs):
        resolved = yield self._resolveUPNBindDN(request)
        result = yield super().handle_LDAPBindRequest(resolved, *args, **kwargs)
        return result

    @defer.inlineCallbacks
    def _resolveUPNBindDN(self, request):
        """
        If ``request`` looks like a UPN bind, resolve it to a real BIND DN.

        A UPN takes the form ``User.Name@ad.example.tld``: it contains an
        ``@`` but no ``,``, so it is not a valid distinguished name. When
        the shape matches, search the directory for the entry whose
        ``userPrincipalName`` matches and return a rewritten
        :class:`LDAPBindRequest` targeting that entry's DN. Otherwise
        return ``request`` unchanged so the caller can fall through to the
        normal DN-based bind path.
        """
        if b"@" not in request.dn or b"," in request.dn:
            # Not a UPN request; leave the DN alone.
            return request

        root = interfaces.IConnectedLDAPEntry(self.factory)
        filter_text = b"(" + self._loginAttribute + b"=" + request.dn + b")"
        results = yield root.search(filterText=filter_text)

        if len(results) != 1:
            # No unambiguous UPN match; fall through to the requested BIND
            # DN and let the stock handler reject it as usual.
            return request

        return pureldap.LDAPBindRequest(
            version=request.version,
            dn=results[0].dn.getText(),
            auth=request.auth,
            tag=request.tag,
            sasl=request.sasl,
        )
