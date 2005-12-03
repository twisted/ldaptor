from twisted.internet import defer, error
from twisted.python.failure import Failure
from ldaptor import interfaces, entry, ldapfilter, entryhelpers
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol

class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""

class ReadOnlyInMemoryLDAPEntry(entry.EditableLDAPEntry,
                                entryhelpers.DiffTreeMixin,
                                entryhelpers.SubtreeFromChildrenMixin,
                                entryhelpers.MatchMixin,
                                ):
    __implements__ = (interfaces.IConnectedLDAPEntry,
                      )

    def __init__(self, *a, **kw):
        entry.BaseLDAPEntry.__init__(self, *a, **kw)
        self._parent = None
        self._children = []

    def parent(self):
        return self._parent

    def children(self, callback=None):
        if callback is None:
            return defer.succeed(self._children[:])
        else:
            for c in self._children:
                callback(c)
            return defer.succeed(None)

    def lookup(self, dn):
        if not self.dn.contains(dn):
            return defer.fail(ldaperrors.LDAPNoSuchObject(dn))
        if dn == self.dn:
            return defer.succeed(self)

        for c in self._children:
            if c.dn.contains(dn):
                return c.lookup(dn)

        return defer.fail(ldaperrors.LDAPNoSuchObject(dn))

    def search(self,
	       filterText=None,
	       filterObject=None,
	       attributes=(),
	       scope=None,
	       derefAliases=None,
	       sizeLimit=0,
	       timeLimit=0,
	       typesOnly=0,
	       callback=None):
	if filterObject is None and filterText is None:
	    filterObject=pureldap.LDAPFilterMatchAll
	elif filterObject is None and filterText is not None:
	    filterObject=ldapfilter.parseFilter(filterText)
	elif filterObject is not None and filterText is None:
	    pass
	elif filterObject is not None and filterText is not None:
	    f=ldapfilter.parseFilter(filterText)
	    filterObject=pureldap.LDAPFilter_and((f, filterObject))

        if scope is None:
            scope = pureldap.LDAP_SCOPE_wholeSubtree
        if derefAliases is None:
            derefAliases = pureldap.LDAP_DEREF_neverDerefAliases

        # choose iterator: base/children/subtree
        if scope == pureldap.LDAP_SCOPE_wholeSubtree:
            iterator = self.subtree
        elif scope == pureldap.LDAP_SCOPE_singleLevel:
            iterator = self.children
        elif scope == pureldap.LDAP_SCOPE_baseObject:
            def iterateSelf(callback):
                callback(self)
                return defer.succeed(None)
            iterator = iterateSelf
        else:
            raise ldaperrors.LDAPProtocolError, \
                  'unknown search scope: %r' % scope

        results = []
        if callback is None:
            matchCallback = results.append
        else:
            matchCallback = callback

        # gather results, send them
        def _tryMatch(entry):
            if entry.match(filterObject):
                matchCallback(entry)

        d = iterator(callback=_tryMatch)

        if callback is None:
            return defer.succeed(results)
        else:
            return defer.succeed(None)

    def fetch(self, *attributes):
        return defer.succeed(self)

    def addChild(self, rdn, attributes):
        """TODO ugly API. Returns the created entry."""
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        for c in self._children:
            if c.dn.split()[0] == rdn:
                raise ldaperrors.LDAPEntryAlreadyExists, c.dn
        dn = distinguishedname.DistinguishedName(listOfRDNs=
                                                 (rdn,)
                                                 +self.dn.split())
        e = ReadOnlyInMemoryLDAPEntry(dn, attributes)
        e._parent = self
        self._children.append(e)
        return e

    def _delete(self):
        if self._parent is None:
            raise LDAPCannotRemoveRootError
        if self._children:
            raise ldaperrors.LDAPNotAllowedOnNonLeaf, self.dn
        return self._parent.deleteChild(self.dn.split()[0])

    def delete(self):
        return defer.maybeDeferred(self._delete)

    def _deleteChild(self, rdn):
        if not isinstance(rdn, distinguishedname.RelativeDistinguishedName):
            rdn = distinguishedname.RelativeDistinguishedName(stringValue=rdn)
        for c in self._children:
            if c.dn.split()[0] == rdn:
                self._children.remove(c)
                return c
        raise ldaperrors.LDAPNoSuchObject, rdn

    def deleteChild(self, rdn):
        return defer.maybeDeferred(self._deleteChild, rdn)


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
        self.db = None #do not access this via db, just to make sure you respect the ordering
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
        return reason # pass the error (abort) by default

    def addFailed(self, reason, entry):
        return reason # pass the error (abort) by default

    def connectionLost(self, reason):
        super(InMemoryLDIFProtocol, self).connectionLost(reason)
        if not reason.check(error.ConnectionDone):
            self._deferred.addCallback(lambda db: reason)
        else:
            self._deferred.chainDeferred(self.completed)

        del self._deferred # invalidate it to flush out bugs

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
