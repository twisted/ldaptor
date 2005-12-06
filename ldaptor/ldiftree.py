"""
Manage LDAP data as a tree of LDIF files.
"""
import os, errno, sets
from zope.interface import implements
from twisted.internet import defer, error
from twisted.python import failure
from ldaptor import entry, interfaces, attributeset, entryhelpers
from ldaptor.protocols.ldap import ldifprotocol, distinguishedname, ldaperrors
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
    def __init__(self):
        self.done = False
        self.seen = []

    def gotEntry(self, obj):
        self.seen.append(obj)

    def connectionLost(self, reason):
        self.done = True

def get(path, dn):
    return defer.maybeDeferred(_get, path, dn)
def _get(path, dn):
    dn = distinguishedname.DistinguishedName(dn)
    l = list(dn.split())
    assert len(l) >= 1
    l.reverse()

    parser = StoreParsedLDIF()

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

    assert parser.done
    entries = parser.seen
    if len(entries) == 0:
        raise LDIFTreeEntryContainsNoEntries
    elif len(entries) > 1:
        raise LDIFTreeEntryContainsMultipleEntries, entries
    else:
        return entries[0]

def _putEntry(fileName, entry):
    """fileName is without extension."""
    tmp = fileName + '.' + tempName() + '.tmp'
    f = file(tmp, 'w')
    f.write(str(entry))
    f.close()
    os.rename(tmp, fileName+'.ldif')
    # TODO atomicity

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
            except OSError, e:
                if e.errno == errno.EEXIST:
                    # we lost a race to create the directory, safe to ignore
                    pass
                else:
                    raise
    else:
        parentDir = path
    return _putEntry(os.path.join(parentDir, '%s'%entryRDN), entry)

def put(path, entry):
    return defer.execute(_put, path, entry)

class LDIFTreeEntry(entry.EditableLDAPEntry,
                    entryhelpers.DiffTreeMixin,
                    entryhelpers.SubtreeFromChildrenMixin,
                    entryhelpers.MatchMixin,
                    entryhelpers.SearchByTreeWalkingMixin,
                    ):
    implements(interfaces.IConnectedLDAPEntry)

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

        parser = StoreParsedLDIF()

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
        assert parser.done

        entries = parser.seen
        if len(entries) == 0:
            raise LDIFTreeEntryContainsNoEntries
        elif len(entries) > 1:
            raise LDIFTreeEntryContainsMultipleEntries, entries
        else:
            # TODO ugliness and all of its friends
            for k,v in entries[0].items():
                self._attributes[k] = attributeset.LDAPAttributeSet(k, v)

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
            seen = sets.Set()
            for fn in filenames:
                base, ext = os.path.splitext(fn)
                if ext not in ['.dir', '.ldif']:
                    continue
                if base in seen:
                    continue
                seen.add(base)

                dn = distinguishedname.DistinguishedName(
                    listOfRDNs=((distinguishedname.RelativeDistinguishedName(base),)
                                + self.dn.split()))
                e = self.__class__(os.path.join(self.path, base + '.dir'), dn)
                children.append(e)
        return children

    def _children(self, callback=None):
        children = self._sync_children()
        if callback is None:
            return children
        else:
            for c in children:
                callback(c)
            return None

    def children(self, callback=None):
        return defer.maybeDeferred(self._children, callback=callback)

    def lookup(self, dn):
        dn = distinguishedname.DistinguishedName(dn)
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
            raise ldaperrors.LDAPNotAllowedOnNonLeaf(
                'Cannot remove entry with children: %s' % self.dn)
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

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__,
                               self.path,
                               str(self.dn))

    def __cmp__(self, other):
        if not isinstance(other, LDIFTreeEntry):
            return NotImplemented
        return cmp(self.dn, other.dn)

    def commit(self):
        assert self.path.endswith('.dir')
        entryPath = self.path[:-len('.dir')]
        return defer.maybeDeferred(_putEntry, entryPath, self)

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
