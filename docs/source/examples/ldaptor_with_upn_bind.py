"""
An ldaptor LDAP server which can authenticate based on UPN, as AD does.

The LDAP entry needs to have the `userPrincipalName` attribute set.

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
"""
from __future__ import absolute_import

from ldaptor import interfaces
from ldaptor.protocols import pureldap
from twisted.internet import defer
from ldaptor.protocols.ldap.ldapserver import LDAPServer


class LDAPServerWithUPNBind(LDAPServer, object):
    """
    An LDAP server which support BIND using UPN similar to AD.
    """

    _loginAttribute = b"userPrincipalName"

    @defer.inlineCallbacks
    def handle_LDAPBindRequest(self, request, *args, **kwargs):
        @defer.inlineCallbacks
        def _request():
            if not (b"@" in request.dn and b"," not in request.dn):
                defer.returnValue(request)
            root = interfaces.IConnectedLDAPEntry(self.factory)
            # This might be an UPN request.
            filter_text = b"(" + self._loginAttribute + b"=" + request.dn + b")"
            results = yield root.search(filterText=filter_text)
            if len(results) != 1:
                defer.returnValue(request)

            defer.returnValue(
                pureldap.LDAPBindRequest(
                    version=request.version,
                    dn=results[0].dn.getText(),
                    auth=request.auth,
                    tag=request.tag,
                    sasl=request.sasl,
                )
            )

        defer.returnValue(
            (
                yield super(LDAPServerWithUPNBind, self).handle_LDAPBindRequest(
                    (yield _request()), *args, **kwargs
                )
            )
        )
