from twisted.python.failure import Failure
from twisted.internet import error
from ldaptor.protocols.ldap import ldifprotocol
from ldaptor import delta, entry

WAIT_FOR_CHANGETYPE = b'WAIT_FOR_CHANGETYPE'
WAIT_FOR_MOD_SPEC = b'WAIT_FOR_MOD_SPEC'
IN_MOD_SPEC = b'IN_MOD_SPEC'
IN_ADD_ENTRY = b'IN_ADD_ENTRY'
IN_DELETE = b'IN_DELETE'

class LDIFDeltaMissingChangeTypeError(ldifprotocol.LDIFParseError):
    """LDIF delta entry has no changetype."""
    pass

class LDIFDeltaUnknownModificationError(ldifprotocol.LDIFParseError):
    """LDIF delta modification has unknown mod-spec."""
    pass

class LDIFDeltaModificationMissingEndDashError(ldifprotocol.LDIFParseError):
    """LDIF delta modification has no ending dash."""
    pass

class LDIFDeltaModificationDifferentAttributeTypeError(ldifprotocol.LDIFParseError):
    """The attribute type for the change is not the as in the mod-spec header line."""
    pass

class LDIFDeltaAddMissingAttributesError(ldifprotocol.LDIFParseError):
    """Add operation needs to have atleast one attribute type and value."""
    pass

class LDIFDeltaDeleteHasJunkAfterChangeTypeError(ldifprotocol.LDIFParseError):
    """Delete operation takes no attribute types or values."""
    pass

class LDIFDelta(ldifprotocol.LDIF):
    def state_WAIT_FOR_DN(self, line):
        super(LDIFDelta, self).state_WAIT_FOR_DN(line)
        if self.mode == ldifprotocol.IN_ENTRY:
            self.mode = WAIT_FOR_CHANGETYPE

    def state_WAIT_FOR_CHANGETYPE(self, line):
        assert self.dn is not None, 'self.dn must be set when in entry'
        assert self.data is not None, 'self.data must be set when in entry'

        if line == '':
            raise LDIFDeltaMissingChangeTypeError(self.dn)

        key, val = self._parseLine(line)

        if key != b'changetype':
            raise LDIFDeltaMissingChangeTypeError(self.dn, key, val)

        if val == b'modify':
            self.modifications = []
            self.mode = WAIT_FOR_MOD_SPEC
        elif val == b'add':
            self.mode = IN_ADD_ENTRY
        elif val == b'delete':
            self.mode = IN_DELETE
        elif val == b'modrdn' or val == b'moddn':
            raise NotImplementedError()  # TODO

    MOD_SPEC_TO_DELTA = {
        b'add': delta.Add,
        b'delete': delta.Delete,
        b'replace': delta.Replace,
        }

    def state_WAIT_FOR_MOD_SPEC(self, line):
        if line == '':
            # end of entry
            self.mode = ldifprotocol.WAIT_FOR_DN
            m = delta.ModifyOp(dn=self.dn,
                               modifications=self.modifications)
            self.dn = None
            self.data = None
            self.modifications = None
            self.gotEntry(m)
            return

        key, val = self._parseLine(line)

        if key not in self.MOD_SPEC_TO_DELTA:
            raise LDIFDeltaUnknownModificationError(self.dn, key)

        self.mod_spec = key
        self.mod_spec_attr = val
        self.mod_spec_data = []
        self.mode = IN_MOD_SPEC

    def state_IN_MOD_SPEC(self, line):
        if line == b'':
            raise LDIFDeltaModificationMissingEndDashError()

        if line == b'-':
            mod = self.MOD_SPEC_TO_DELTA[self.mod_spec]
            de = mod(self.mod_spec_attr, self.mod_spec_data)
            self.modifications.append(de)
            del self.mod_spec
            del self.mod_spec_attr
            del self.mod_spec_data
            self.mode = WAIT_FOR_MOD_SPEC
            return

        key, val = self._parseLine(line)

        if key != self.mod_spec_attr:
            raise LDIFDeltaModificationDifferentAttributeTypeError(
                key, self.mod_spec_attr)

        self.mod_spec_data.append(val)

    def state_IN_ADD_ENTRY(self, line):
        assert self.dn is not None, 'self.dn must be set when in entry'
        assert self.data is not None, 'self.data must be set when in entry'

        if line == b'':
            # end of entry
            if not self.data:
                raise LDIFDeltaAddMissingAttributesError(self.dn)
            self.mode = ldifprotocol.WAIT_FOR_DN
            o = delta.AddOp(entry.BaseLDAPEntry(dn=self.dn,
                                                attributes=self.data))
            self.dn = None
            self.data = None
            self.gotEntry(o)
            return

        key, val = self._parseLine(line)

        if not key in self.data:
            self.data[key] = []

        self.data[key].append(val)

    def state_IN_DELETE(self, line):
        assert self.dn is not None, 'self.dn must be set when in entry'

        if line == b'':
            # end of entry
            self.mode = ldifprotocol.WAIT_FOR_DN
            o = delta.DeleteOp(dn=self.dn)
            self.dn = None
            self.data = None
            self.gotEntry(o)
            return

        raise LDIFDeltaDeleteHasJunkAfterChangeTypeError(
                self.dn, line)

def fromLDIFFile(f):
    """Read LDIF data from a file."""

    p = LDIFDelta()
    l = []
    p.gotEntry = l.append
    while 1:
        data = f.read()
        if not data:
            break
        p.dataReceived(data)
    p.connectionLost(Failure(error.ConnectionDone()))

    return l
