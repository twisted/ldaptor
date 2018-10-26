from twisted.internet import defer, error
from twisted.python.failure import Failure
from zope.interface import implementer

from ldaptor import interfaces, entry, entryhelpers
from ldaptor.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol


class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""


@implementer(interfaces.IConnectedLDAPEntry)
class ReadOnlyInMemoryLDAPEntry(entry.EditableLDAPEntry,
                                entryhelpers.DiffTreeMixin,
                                entryhelpers.SubtreeFromChildrenMixin,
                                entryhelpers.MatchMixin,
                                entryhelpers.SearchByTreeWalkingMixin,
                                ):

    def __init__(self, *a, **kw):
        entry.BaseLDAPEntry.__init__(self, *a, **kw)
        self._parent = None
        self._children = {}

    def parent(self):
        return self._parent

    def children(self, callback=None):
        if callback is None:
            return defer.succeed(list(self._children.values()))
        else:
            for c in self._children.values():
                callback(c)
            return defer.succeed(None)

    def _lookup(self, dn):
        if not self.dn.contains(dn):
            raise ldaperrors.LDAPNoSuchObject(dn)
        if dn == self.dn:
            return defer.succeed(self)

        for c in self._children.values():
            if c.dn.contains(dn):
                return c.lookup(dn)

        raise ldaperrors.LDAPNoSuchObject(dn)

    def lookup(self, dn):
        return defer.maybeDeferred(self._lookup, dn)

    def fetch(self, *attributes):
        return defer.succeed(self)

    def addChild(self, rdn, attributes):
        """TODO ugly API. Returns the created entry."""
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        rdn_str = rdn.toWire()
        if rdn_str in self._children:
            raise ldaperrors.LDAPEntryAlreadyExists(self._children[rdn_str].dn)
        dn = distinguishedname.DistinguishedName(
            listOfRDNs=(rdn,) + self.dn.split())
        e = ReadOnlyInMemoryLDAPEntry(dn, attributes)
        e._parent = self
        self._children[rdn_str] = e
        return e

    def _delete(self):
        if self._parent is None:
            raise LDAPCannotRemoveRootError()
        if self._children:
            raise ldaperrors.LDAPNotAllowedOnNonLeaf(self.dn)
        return self._parent.deleteChild(self.dn.split()[0])

    def delete(self):
        return defer.maybeDeferred(self._delete)

    def _deleteChild(self, rdn):
        if not isinstance(rdn, distinguishedname.RelativeDistinguishedName):
            rdn = distinguishedname.RelativeDistinguishedName(stringValue=rdn)
        rdn_str = rdn.toWire()
        try:
            return self._children.pop(rdn_str)
        except KeyError:
            raise ldaperrors.LDAPNoSuchObject(rdn)

    def deleteChild(self, rdn):
        return defer.maybeDeferred(self._deleteChild, rdn)

    def _move(self, newDN):
        if not isinstance(newDN, distinguishedname.DistinguishedName):
            newDN = distinguishedname.DistinguishedName(stringValue=newDN)
        if newDN.up() != self.dn.up():
            # climb up the tree to root
            root = self
            while root._parent is not None:
                root = root._parent
            d = defer.maybeDeferred(root.lookup, newDN.up())
        else:
            d = defer.succeed(None)
        d.addCallback(self._move2, newDN)
        return d

    def _move2(self, newParent, newDN):
        if newParent is not None:
            newParent._children[newDN.split()[0].toWire()] = self
            del self._parent._children[self.dn.split()[0].toWire()]
        # remove old RDN attributes
        for attr in self.dn.split()[0].split():
            self[attr.attributeType].remove(attr.value)
        # add new RDN attributes
        for attr in newDN.split()[0].split():
            # TODO what if the key does not exist?
            self[attr.attributeType].add(attr.value)
        self.dn = newDN
        return self

    def move(self, newDN):
        return defer.maybeDeferred(self._move, newDN)

    def commit(self):
        return defer.succeed(True)


class InMemoryLDIFProtocol(ldifprotocol.LDIF):
    """
    Receive LDIF data and gather results into an ReadOnlyInMemoryLDAPEntry.

    You can override lookupFailed and addFailed to provide smarter
    error handling. They are called as Deferred errbacks; returning
    the reason causes error to pass onward and abort the whole
    operation. Returning None from lookupFailed skips that entry, but
    continues loading.

    When the full LDIF data has been read, the completed Deferred will
    trigger.
    """

    def __init__(self):
        # Do not access this via db, just to make sure you respect the ordering
        self.db = None
        self._deferred = defer.Deferred()
        self.completed = defer.Deferred()

    def _addEntry(self, db, entry):
        d = db.lookup(entry.dn.up())
        d.addErrback(self.lookupFailed, entry)

        def _add(parent, entry):
            if parent is not None:
                parent.addChild(rdn=entry.dn.split()[0],
                                attributes=entry)

        d.addCallback(_add, entry)
        d.addErrback(self.addFailed, entry)

        def _passDB(_, db):
            return db

        d.addCallback(_passDB, db)
        return d

    def gotEntry(self, entry):
        if self.db is None:
            # first entry, create the db, prepare to process the rest
            self.db = ReadOnlyInMemoryLDAPEntry(
                dn=entry.dn,
                attributes=entry)
            self._deferred.callback(self.db)
        else:
            self._deferred.addCallback(self._addEntry, entry)

    def lookupFailed(self, reason, entry):
        return reason  # pass the error (abort) by default

    def addFailed(self, reason, entry):
        return reason  # pass the error (abort) by default

    def connectionLost(self, reason):
        super(InMemoryLDIFProtocol, self).connectionLost(reason)
        if not reason.check(error.ConnectionDone):
            self._deferred.addCallback(lambda db: reason)
        else:
            self._deferred.chainDeferred(self.completed)

        del self._deferred  # invalidate it to flush out bugs


def fromLDIFFile(f):
    """Read LDIF data from a file."""

    p = InMemoryLDIFProtocol()
    while 1:
        data = f.read()
        if not data:
            break
        p.dataReceived(data)
    p.connectionLost(Failure(error.ConnectionDone()))

    return p.completed
