"""
Manage LDAP data as a tree of LDIF files.
"""
import os, errno
from twisted.internet import defer, error
from twisted.python import failure
from ldaptor import entry, interfaces
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldifprotocol, ldif, distinguishedname, ldaperrors
from twisted.mail.maildir import _generateMaildirName as tempName

class LDIFTreeEntryContainsMultipleEntries(Exception):
    """LDIFTree entry contains multiple LDIF entries."""

class LDIFTreeEntryContainsNoEntries(Exception):
    """LDIFTree entry does not contain a valid LDIF entry."""

class LDIFTreeNoSuchObject(Exception):
    # TODO combine with standard LDAP errors
    """LDIFTree does not contain such entry."""

class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""
    # TODO share with ldaptor.inmemory?


class StoreParsedLDIF(ldifprotocol.LDIF):
    def __init__(self, deferred):
        self.deferred = deferred
        self.seen = []
        
    def gotEntry(self, obj):
        self.seen.append(obj)

    def connectionLost(self, reason):
        self.deferred.callback(self.seen)

def get(path, dn):
    l = list(dn.split())
    assert len(l) >= 1
    l.reverse()

    d = defer.Deferred()
    parser = StoreParsedLDIF(d)

    entry = os.path.join(path,
                         *['%s.dir'%rdn for rdn in l[:-1]])
    entry = os.path.join(entry, '%s.ldif'%l[-1])
    f = file(entry)
    while 1:
        data = f.read(8192)
        if not data:
            break
        parser.dataReceived(data)
    parser.connectionLost(failure.Failure(error.ConnectionDone))

    def _thereCanOnlyBeOne(entries):
        if len(entries) == 0:
            raise LDIFTreeEntryContainsNoEntries
        elif len(entries) > 1:
            raise LDIFTreeEntryContainsMultipleEntries, entries
        else:
            return entries[0]
    d.addCallback(_thereCanOnlyBeOne)
    return d

def _put(path, entry):
    l = list(entry.dn.split())
    assert len(l) >= 1
    l.reverse()

    entryRDN = l.pop()
    if l:
        grandParent = os.path.join(path,
                                   *['%s.dir'%rdn for rdn in l[:-1]])
        parentEntry = os.path.join(grandParent, '%s.ldif' % l[-1])
        parentDir = os.path.join(grandParent, '%s.dir' % l[-1])
        if not os.path.exists(parentDir):
            if not os.path.exists(parentEntry):
                raise LDIFTreeNoSuchObject, entry.dn.up()
            try:
                os.mkdir(parentDir)
            except IOError:
                if e.errno == errno.EEXIST:
                    pass
                else:
                    raise
    else:
        parentDir = path
    fileName = os.path.join(parentDir, '%s'%entryRDN)
    tmp = fileName + '.' + tempName() + '.tmp'
    f = file(tmp, 'w')
    f.write(str(entry))
    f.close()
    os.rename(tmp, fileName+'.ldif')
    # TODO atomicity

def put(path, entry):
    return defer.execute(_put, path, entry)

class LDIFTreeEntry(entry.EditableLDAPEntry):
    __implements__ = (interfaces.IConnectedLDAPEntry,
                      )
    def __init__(self, path, dn=None, *a, **kw):
        if dn is None:
            dn = ''
        entry.BaseLDAPEntry.__init__(self, dn, *a, **kw)
        self.path = path
        if dn != '': #TODO DistinguishedName.__nonzero__
            self._load()

    def _load(self):
        assert self.path.endswith('.dir')
        entryPath = '%s.ldif' % self.path[:-len('.dir')]

        d = defer.Deferred()
        parser = StoreParsedLDIF(d)

        try:
            f = file(entryPath)
        except IOError, e:
            if e.errno == errno.ENOENT:
                return
            else:
                raise
        while 1:
            data = f.read(8192)
            if not data:
                break
            parser.dataReceived(data)
        parser.connectionLost(failure.Failure(error.ConnectionDone))

        def _thereCanOnlyBeOne(entries):
            if len(entries) == 0:
                raise LDIFTreeEntryContainsNoEntries
            elif len(entries) > 1:
                raise LDIFTreeEntryContainsMultipleEntries, entries
            else:
                return entries[0]
        d.addCallback(_thereCanOnlyBeOne)

        # TODO ugliness and all of its friends
        assert d.called
        from twisted.trial import util
        e = util.wait(d)
        for k,v in e.items():
            self._attributes[k] = list(v)

    def parent(self):
        # TODO add __nonzero__ to DistinguishedName
        if self.dn == '':
            # root
            return None
        else:
            parentPath, _ = os.path.split(self.path)
            return self.__class__(parentPath, self.dn.up())

    def _sync_children(self):
        children = []
        try:
            filenames = os.listdir(self.path)
        except OSError, e:
            if e.errno == errno.ENOENT:
                pass
            else:
                raise
        else:
            for fn in filenames:
                if fn.endswith('.ldif'):
                    dirname = '%s.dir' % fn[:-len('.ldif')]
                    dn = distinguishedname.DistinguishedName(
                        listOfRDNs=((distinguishedname.RelativeDistinguishedName(fn[:-len('.ldif')]),)
                                    + self.dn.split()))
                    e = self.__class__(os.path.join(self.path, dirname), dn)
                    children.append(e)
        return children

    def children(self, callback=None):
        children = self._sync_children()
        if callback is None:
            return defer.succeed(children)
        else:
            for c in children:
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

        it = dn.split()
        me = self.dn.split()
        assert len(it) > len(me)
        assert ((len(me)==0) or (it[-len(me):] == me))
        rdn = it[-len(me)-1]
        path = os.path.join(self.path, '%s.dir' % rdn)
        entry = os.path.join(self.path, '%s.ldif' % rdn)
        if not os.path.isdir(path) and not os.path.isfile(entry):
            return defer.fail(ldaperrors.LDAPNoSuchObject(dn))
        else:
            childDN = distinguishedname.DistinguishedName(listOfRDNs=(rdn,)+me)
            c = self.__class__(path, childDN)
            return c.lookup(dn)


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
                callback(entry)

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

    def _addChild(self, rdn, attributes):
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        for c in self._sync_children():
            if c.dn.split()[0] == rdn:
                raise ldaperrors.LDAPEntryAlreadyExists, c.dn

        dn = distinguishedname.DistinguishedName(listOfRDNs=
                                                 (rdn,)
                                                 +self.dn.split())
        e = entry.BaseLDAPEntry(dn, attributes)
        if not os.path.exists(self.path):
            os.mkdir(self.path)
        fileName = os.path.join(self.path, '%s' % rdn)
        tmp = fileName + '.' + tempName() + '.tmp'
        f = file(tmp, 'w')
        f.write(str(e))
        f.close()
        os.rename(tmp, fileName+'.ldif')
        # TODO atomicity

        dirName = os.path.join(self.path, '%s.dir' % rdn)

        e = self.__class__(dirName, dn)
        return e

    def addChild(self, rdn, attributes):
        d = self._addChild(rdn, attributes)
        return d

    def _delete(self):
        if self.dn == '': ##TODO DistinguishedName __nonzero__
            raise LDAPCannotRemoveRootError
        if self._sync_children():
            raise ldaperrors.LDAPNotAllowedOnNonLeaf, self.dn
        assert self.path.endswith('.dir')
        entryPath = '%s.ldif' % self.path[:-len('.dir')]
        os.remove(entryPath)
        return self

    def delete(self):
        return defer.maybeDeferred(self._delete)

    def _deleteChild(self, rdn):
        if not isinstance(rdn, distinguishedname.RelativeDistinguishedName):
            rdn = distinguishedname.RelativeDistinguishedName(stringValue=rdn)
        for c in self._sync_children():
            if c.dn.split()[0] == rdn:
                return c.delete()
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

if __name__ == '__main__':
    """
    Demonstration LDAP server; serves an LDIFTree from given directory
    over LDAP on port 10389.
    """

    from twisted.internet import reactor, protocol
    from twisted.python import log
    import sys
    log.startLogging(sys.stderr)

    from twisted.python import components
    from twisted.trial import util
    from ldaptor.protocols.ldap import ldapserver

    path = sys.argv[1]
    db = LDIFTreeEntry(path)

    class LDAPServerFactory(protocol.ServerFactory):
        def __init__(self, root):
            self.root = root

    class MyLDAPServer(ldapserver.LDAPServer):
        debug = True

    components.registerAdapter(lambda x: x.root,
                               LDAPServerFactory,
                               interfaces.IConnectedLDAPEntry)

    factory = LDAPServerFactory(db)
    factory.protocol = MyLDAPServer
    reactor.listenTCP(10389, factory)
    reactor.run()
