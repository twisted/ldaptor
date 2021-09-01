"""
Manage LDAP data as a tree of LDIF files.
"""
import errno
import os
import uuid

from twisted.internet import defer, error
from twisted.python import failure
from zope.interface import implementer

from ldaptor import entry, interfaces, attributeset, entryhelpers
from ldaptor.protocols.ldap import ldifprotocol, distinguishedname, ldaperrors
from ldaptor._encoder import to_unicode


class LDIFTreeEntryContainsMultipleEntries(Exception):
    """LDIFTree entry contains multiple LDIF entries."""


class LDIFTreeEntryContainsNoEntries(Exception):
    """LDIFTree entry does not contain a valid LDIF entry."""


class LDIFTreeNoSuchObject(Exception):
    """LDIFTree does not contain such entry."""


class LDAPCannotRemoveRootError(ldaperrors.LDAPNamingViolation):
    """Cannot remove root of LDAP tree"""


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
    path = to_unicode(path)
    dn = distinguishedname.DistinguishedName(dn)
    l = list(dn.split())
    assert len(l) >= 1
    l.reverse()

    parser = StoreParsedLDIF()

    entry = os.path.join(path, *("%s.dir" % rdn.getText() for rdn in l[:-1]))
    entry = os.path.join(entry, "%s.ldif" % l[-1].getText())
    f = open(entry, "rb")
    while 1:
        data = f.read(8192)
        if not data:
            break
        parser.dataReceived(data)
    parser.connectionLost(failure.Failure(error.ConnectionDone()))

    assert parser.done
    entries = parser.seen
    if len(entries) == 0:
        raise LDIFTreeEntryContainsNoEntries()
    elif len(entries) > 1:
        raise LDIFTreeEntryContainsMultipleEntries(entries)
    else:
        return entries[0]


def _putEntry(fileName, entry):
    """fileName is without extension."""
    tmp = f"{fileName}.{str(uuid.uuid4())}.tmp"
    f = open(tmp, "wb")
    f.write(entry.toWire())
    f.close()
    os.rename(tmp, fileName + ".ldif")
    return True


def _put(path, entry):
    path = to_unicode(path)
    l = list(entry.dn.split())
    assert len(l) >= 1
    l.reverse()

    entryRDN = l.pop()
    if l:
        grandParent = os.path.join(path, *("%s.dir" % rdn.getText() for rdn in l[:-1]))
        parentEntry = os.path.join(grandParent, "%s.ldif" % l[-1].getText())
        parentDir = os.path.join(grandParent, "%s.dir" % l[-1].getText())
        if not os.path.exists(parentDir):
            if not os.path.exists(parentEntry):
                raise LDIFTreeNoSuchObject(entry.dn.up())
            try:
                os.mkdir(parentDir)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    # we lost a race to create the directory, safe to ignore
                    pass
                else:
                    raise
    else:
        parentDir = path
    return _putEntry(os.path.join(parentDir, "%s" % entryRDN.getText()), entry)


def put(path, entry):
    return defer.execute(_put, path, entry)


@implementer(interfaces.IConnectedLDAPEntry)
class LDIFTreeEntry(
    entry.EditableLDAPEntry,
    entryhelpers.DiffTreeMixin,
    entryhelpers.SubtreeFromChildrenMixin,
    entryhelpers.MatchMixin,
    entryhelpers.SearchByTreeWalkingMixin,
):
    def __init__(self, path, dn=None, *a, **kw):
        if dn is None:
            dn = ""
        entry.BaseLDAPEntry.__init__(self, dn, *a, **kw)
        self.path = to_unicode(path)
        if self.dn != "":
            self._load()

    def _load(self):
        assert self.path.endswith(".dir")
        entryPath = "%s.ldif" % self.path[: -len(".dir")]

        parser = StoreParsedLDIF()

        try:
            f = open(entryPath, "rb")
        except OSError as e:
            if e.errno == errno.ENOENT:
                return
            else:
                raise
        while 1:
            data = f.read(8192)
            if not data:
                break
            parser.dataReceived(data)
        parser.connectionLost(failure.Failure(error.ConnectionDone()))
        assert parser.done

        entries = parser.seen
        if len(entries) == 0:
            raise LDIFTreeEntryContainsNoEntries()
        elif len(entries) > 1:
            raise LDIFTreeEntryContainsMultipleEntries(entries)
        else:
            for k, v in entries[0].items():
                self._attributes[k] = attributeset.LDAPAttributeSet(k, v)

    def parent(self):
        if self.dn == "":
            # root
            return None
        else:
            parentPath, _ = os.path.split(self.path)
            return self.__class__(parentPath, self.dn.up())

    def _sync_children(self):
        children = []
        try:
            filenames = os.listdir(self.path)
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass
            else:
                raise
        else:
            seen = set()
            for fn in filenames:
                base, ext = os.path.splitext(fn)
                if ext not in [".dir", ".ldif"]:
                    continue
                if base in seen:
                    continue
                seen.add(base)

                dn = distinguishedname.DistinguishedName(
                    listOfRDNs=(
                        (distinguishedname.RelativeDistinguishedName(base),)
                        + self.dn.split()
                    )
                )
                e = self.__class__(os.path.join(self.path, base + ".dir"), dn)
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
            return defer.fail(ldaperrors.LDAPNoSuchObject(dn.getText()))
        if dn == self.dn:
            return defer.succeed(self)

        it = dn.split()
        me = self.dn.split()
        assert len(it) > len(me)
        assert (len(me) == 0) or (it[-len(me) :] == me)
        rdn = it[-len(me) - 1]
        path = os.path.join(self.path, "%s.dir" % rdn.getText())
        entry = os.path.join(self.path, "%s.ldif" % rdn.getText())
        if not os.path.isdir(path) and not os.path.isfile(entry):
            return defer.fail(ldaperrors.LDAPNoSuchObject(dn.getText()))
        else:
            childDN = distinguishedname.DistinguishedName(listOfRDNs=(rdn,) + me)
            c = self.__class__(path, childDN)
            return c.lookup(dn)

    def _addChild(self, rdn, attributes):
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        for c in self._sync_children():
            if c.dn.split()[0] == rdn:
                raise ldaperrors.LDAPEntryAlreadyExists(c.dn.getText())

        dn = distinguishedname.DistinguishedName(listOfRDNs=(rdn,) + self.dn.split())
        e = entry.BaseLDAPEntry(dn, attributes)
        if not os.path.exists(self.path):
            os.mkdir(self.path)
        fileName = os.path.join(self.path, "%s" % rdn.getText())
        tmp = f"{fileName}.{str(uuid.uuid4())}.tmp"
        f = open(tmp, "wb")
        f.write(e.toWire())
        f.close()
        os.rename(tmp, fileName + ".ldif")
        dirName = os.path.join(self.path, "%s.dir" % rdn.getText())
        e = self.__class__(dirName, dn)
        return e

    def addChild(self, rdn, attributes):
        d = self._addChild(rdn, attributes)
        return d

    def _delete(self):
        if self.dn == "":
            raise LDAPCannotRemoveRootError()
        if self._sync_children():
            raise ldaperrors.LDAPNotAllowedOnNonLeaf(
                "Cannot remove entry with children: %s" % self.dn.getText()
            )
        assert self.path.endswith(".dir")
        entryPath = "%s.ldif" % self.path[: -len(".dir")]
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
        raise ldaperrors.LDAPNoSuchObject(rdn.getText())

    def deleteChild(self, rdn):
        return defer.maybeDeferred(self._deleteChild, rdn)

    def __repr__(self):
        return "{}({!r}, {!r})".format(
            self.__class__.__name__, self.path, self.dn.getText()
        )

    def __lt__(self, other):
        if not isinstance(other, LDIFTreeEntry):
            return NotImplemented
        return self.dn < other.dn

    def __gt__(self, other):
        if not isinstance(other, LDIFTreeEntry):
            return NotImplemented
        return self.dn > other.dn

    def commit(self):
        assert self.path.endswith(".dir")
        entryPath = self.path[: -len(".dir")]
        d = defer.maybeDeferred(_putEntry, entryPath, self)

        def eb_(err):
            from twisted.python import log

            log.msg(f"[ERROR] Could not commit entry: {self.dn}.")
            return False

        d.addErrback(eb_)
        return d

    def move(self, newDN):
        return defer.maybeDeferred(self._move, newDN)

    def _move(self, newDN):
        if not isinstance(newDN, distinguishedname.DistinguishedName):
            newDN = distinguishedname.DistinguishedName(stringValue=newDN)
        if newDN.up() != self.dn.up():
            # climb up the tree to root
            rootDN = self.dn
            rootPath = self.path
            while rootDN != "":
                rootDN = rootDN.up()
                rootPath = os.path.dirname(rootPath)
            root = self.__class__(path=rootPath, dn=rootDN)
            d = defer.maybeDeferred(root.lookup, newDN.up())
        else:
            d = defer.succeed(None)
        d.addCallback(self._move2, newDN)
        return d

    def _move2(self, newParent, newDN):
        # remove old RDN attributes
        for attr in self.dn.split()[0].split():
            self[attr.attributeType].remove(attr.value)
        # add new RDN attributes
        for attr in newDN.split()[0].split():
            self[attr.attributeType].add(attr.value)
        newRDN = newDN.split()[0]
        srcdir = os.path.dirname(self.path)
        if newParent is None:
            dstdir = srcdir
        else:
            dstdir = newParent.path

        newpath = os.path.join(dstdir, "%s.dir" % newRDN.getText())
        try:
            os.rename(self.path, newpath)
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass
            else:
                raise
        basename, ext = os.path.splitext(self.path)
        assert ext == ".dir"
        os.rename(
            "%s.ldif" % basename, os.path.join(dstdir, "%s.ldif" % newRDN.getText())
        )
        self.dn = newDN
        self.path = newpath
        return self.commit()


if __name__ == "__main__":
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

    components.registerAdapter(
        lambda x: x.root, LDAPServerFactory, interfaces.IConnectedLDAPEntry
    )

    factory = LDAPServerFactory(db)
    factory.protocol = MyLDAPServer
    reactor.listenTCP(10389, factory)
    reactor.run()
