import sets
from twisted.internet import defer, error
from twisted.python.failure import Failure
from ldaptor import interfaces, entry, delta, ldapfilter
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import distinguishedname, ldaperrors, ldifprotocol, ldapsyntax

class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""

class ReadOnlyInMemoryLDAPEntry(entry.EditableLDAPEntry):
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

    def subtree(self, callback=None):
        if callback is None:
            result = []
            d = self.subtree(callback=result.append)
            d.addCallback(lambda _: result)
            return d
        else:
            callback(self)
            d = self.children()
            def _processOneChild(_, children, callback):
                if not children:
                    return None

                c = children.pop()
                d = c.subtree(callback)
                d.addCallback(_processOneChild, children, callback)
            def _gotChildren(children, callback):
                _processOneChild(None, children, callback)
            d.addCallback(_gotChildren, callback)
            return d

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

    def match(self, filter):
        if isinstance(filter, pureldap.LDAPFilter_present):
            return filter.value in self
        elif isinstance(filter, pureldap.LDAPFilter_equalityMatch):
            # TODO case insensitivity etc, different attribute syntaxes
            if filter.attributeDesc.value not in self:
                return False
            if filter.assertionValue.value in self[filter.attributeDesc.value]:
                return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_substrings):
            if filter.type not in self:
                return False
            possibleMatches = self[filter.type]
            substrings = filter.substrings[:]

            if (substrings
                and isinstance(filter.substrings[0],
                               pureldap.LDAPFilter_substrings_initial)):
                possibleMatches = [
                    x[len(filter.substrings[0].value):]
                    for x in possibleMatches
                    if x.startswith(filter.substrings[0].value)
                    ]
                del substrings[0]

            if (substrings
                and isinstance(filter.substrings[-1],
                               pureldap.LDAPFilter_substrings_final)):
                possibleMatches = [
                    x[:-len(filter.substrings[0].value)]
                    for x in possibleMatches
                    if x.endswith(filter.substrings[-1].value)
                    ]
                del substrings[-1]

            while possibleMatches and substrings:
                assert isinstance(substrings[0], pureldap.LDAPFilter_substrings_any)
                r = []
                for possible in possibleMatches:
                    i = possible.find(substrings[0].value)
                    if i >= 0:
                        r.append(possible[i:])
                possibleMatches = r
                del substrings[0]
            if possibleMatches and not substrings:
                return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_greaterOrEqual):
            if filter.attributeDesc not in self:
                return False
            for value in self[filter.attributeDesc]:
                if value  >= filter.assertionValue:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_lessOrEqual):
            if filter.attributeDesc not in self:
                return False
            for value in self[filter.attributeDesc]:
                if value <= filter.assertionValue:
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_and):
            for filt in filter:
                if not self.match(filt):
                    return False
            return True
        elif isinstance(filter, pureldap.LDAPFilter_or):
            for filt in filter:
                if self.match(filt):
                    return True
            return False
        elif isinstance(filter, pureldap.LDAPFilter_not):
            return not self.match(filter.value)
        else:
            raise ldapsyntax.MatchNotImplemented, filter

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

    def _diffTree_gotMyChildren(self, myChildren, other, result):
        d = other.children()
        d.addCallback(self._diffTree_gotBothChildren, myChildren, other, result)
        return d

    def _diffTree_gotBothChildren(self,
                                  otherChildren,
                                  myChildren,
                                  other,
                                  result):
        def rdnToChild(rdn, l):
            r = [x for x in l if x.dn.split()[0] == rdn]
            assert len(r) == 1
            return r[0]

        my = sets.Set([x.dn.split()[0] for x in myChildren])
        his = sets.Set([x.dn.split()[0] for x in otherChildren])

        # differences in common children
        commonRDN = list(my & his)
        commonRDN.sort() # for reproducability only
        d = self._diffTree_commonChildren([
            (rdnToChild(rdn, myChildren), rdnToChild(rdn, otherChildren))
            for rdn in commonRDN
            ], result)

        # added children
        addedRDN = list(his - my)
        addedRDN.sort() # for reproducability only
        d2 = self._diffTree_addedChildren([
            rdnToChild(rdn, otherChildren)
            for rdn in addedRDN
            ], result)
        d.addCallback(lambda _: d2)

        # deleted children
        deletedRDN = list(my - his)
        deletedRDN.sort() # for reproducability only
        d3 = self._diffTree_deletedChildren([
            rdnToChild(rdn, myChildren)
            for rdn in deletedRDN
            ], result)
        d.addCallback(lambda _: d3)

        return d

    def _diffTree_commonChildren(self, children, result):
        if not children:
            return defer.succeed(result)
        first, rest = children[0], children[1:]
        a, b = first
        d = a.diffTree(b, result)
        d.addCallback(lambda _: self._diffTree_commonChildren(rest, result))
        return d

    def _diffTree_addedChildren(self, children, result):
        if not children:
            return result
        first, rest = children[0], children[1:]

        d = first.subtree()
        def _gotSubtree(l, result):
            for c in l:
                o = delta.AddOp(c)
                result.append(o)
            return result
        d.addCallback(_gotSubtree, result)

        d.addCallback(lambda _: self._diffTree_addedChildren(rest, result))
        return d

    def _diffTree_deletedChildren(self, children, result):
        if not children:
            return result
        first, rest = children[0], children[1:]

        d = first.subtree()
        def _gotSubtree(l, result):
            l.reverse() # remove children before their parent
            for c in l:
                o = delta.DeleteOp(c)
                result.append(o)
            return result
        d.addCallback(_gotSubtree, result)

        d.addCallback(lambda _: self._diffTree_deletedChildren(rest, result))
        return d

    def diffTree(self, other, result=None):
        assert self.dn == other.dn, \
               ("diffTree arguments must refer to same LDAP tree:"
                "%r != %r" % (str(self.dn), str(other.dn))
                )
        if result is None:
            result = []

        # differences in root
        rootDiff = self.diff(other)
        if rootDiff is not None:
            result.append(rootDiff)

        d = self.children()
        d.addCallback(self._diffTree_gotMyChildren, other, result)
            
        return d

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
    from twisted.trial import util

    p = InMemoryLDIFProtocol()
    while 1:
        data = f.read()
        if not data:
            break
        p.dataReceived(data)
    p.connectionLost(Failure(error.ConnectionDone()))

    return p.completed
