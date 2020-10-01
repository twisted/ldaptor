from twisted.internet import defer
from ldaptor import numberalloc
from ldaptor.protocols.ldap import ldapsyntax, autofill


class Autofill_posix:  # TODO baseclass
    def __init__(self, baseDN, freeNumberGetter=numberalloc.getFreeNumber):
        self.baseDN = baseDN
        self.freeNumberGetter = freeNumberGetter

    def _cb_gotNumbers(self, r, ldapObject):
        uid, gid = r

        ok, val = uid
        if not ok:
            val.trap()
        ldapObject["uidNumber"] = [str(val)]

        ok, val = gid
        if not ok:
            val.trap()
        ldapObject["gidNumber"] = [str(val)]

    def start(self, ldapObject):
        assert "objectClass" in ldapObject
        if "posixAccount" not in ldapObject["objectClass"]:
            raise autofill.ObjectMissingObjectClassException(ldapObject)

        assert "loginShell" not in ldapObject
        ldapObject["loginShell"] = ["/bin/sh"]

        baseObject = ldapsyntax.LDAPEntry(client=ldapObject.client, dn=self.baseDN)
        d1 = self.freeNumberGetter(baseObject, "uidNumber", min=1000)

        d2 = self.freeNumberGetter(baseObject, "gidNumber", min=1000)

        d = defer.DeferredList([d1, d2], fireOnOneErrback=1)

        # silence the log
        d1.addErrback(lambda x: None)
        d2.addErrback(lambda x: None)

        d.addCallback(self._cb_gotNumbers, ldapObject)
        return d

    def notify(self, ldapObject, attributeType):
        pass
