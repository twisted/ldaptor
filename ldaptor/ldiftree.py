"""
Manage LDAP data as a tree of LDIF files.
"""
import os, errno
from twisted.internet import defer, error
from twisted.python import failure
from ldaptor.protocols.ldap import ldifprotocol, ldif
from twisted.mail.maildir import _generateMaildirName as tempName

class LDIFTreeEntryContainsMultipleEntries(Exception):
    """LDIFTree entry contains multiple LDIF entries."""

class LDIFTreeEntryContainsNoEntries(Exception):
    """LDIFTree entry does not contain a valid LDIF entry."""

class LDIFTreeNoSuchObject(Exception):
    # TODO combine with standard LDAP errors
    """LDIFTree does not contain such entry."""


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
    entry = os.path.join(entry, '%s.entry'%l[-1])
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
        parentEntry = os.path.join(grandParent, '%s.entry' % l[-1])
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
    os.rename(tmp, fileName+'.entry')
    # TODO atomicity

def put(path, entry):
    return defer.execute(_put, path, entry)
