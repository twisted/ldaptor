import base64

from twisted.protocols import basic
from twisted.internet import error

from ldaptor.protocols.ldap import ldapsyntax

class LDIFParseError(Exception):
    """Error parsing LDIF."""

    def __str__(self):
        s = self.__doc__
        if self[:]:
            s = ': '.join([s]+self[:])
        return s

class LDIFLineWithoutSemicolonError(Exception):
    """LDIF line without semicolon seen."""
    pass

class LDIFEntryStartsWithNonDNError(Exception):
    """LDIF entry starts with a non-DN line."""
    pass

class LDIFBadValueError(Exception):
    """Invalid LDIF value format."""
    pass

WAIT_FOR_DN = 'WAIT_FOR_DN'
IN_ENTRY = 'IN_ENTRY'

class LDIF(basic.LineReceiver):
    delimiter='\n'
    mode = WAIT_FOR_DN

    dn = None
    data = None

    def lineReceived(self, line):
        if line.startswith('#'):
            # comments are allowed everywhere
            return

        return getattr(self, 'state_' + self.mode)(line)

    def parseValue(self, val):
        if val.startswith(' '):
            return val[1:]
        elif val.startswith(': '):
            return base64.decodestring(val[2:])
        else:
            raise LDIFBadValueError, val

    def _parseLine(self, line):
        try:
            key, val = line.split(':', 1)
        except ValueError:
            # unpack list of wrong size
            # -> invalid input data
            raise LDIFLineWithoutSemicolonError, line
        val = self.parseValue(val)
        return key, val

    def state_WAIT_FOR_DN(self, line):
        assert self.dn is None, 'self.dn must not be set when waiting for DN'
        assert self.data is None, 'self.data must not be set when waiting for DN'
        if line == '':
            # too many empty lines, but be tolerant
            return

        key, val = self._parseLine(line)

        if key.upper() != 'DN':
            raise LDIFEntryStartsWithNonDNError, line

        self.dn = val
        self.data = {}
        self.mode = IN_ENTRY

    def state_IN_ENTRY(self, line):
        assert self.dn is not None, 'self.dn must be set when in entry'
        assert self.data is not None, 'self.data must be set when in entry'

        if line == '':
            # end of entry
            self.mode = WAIT_FOR_DN
            o = ldapsyntax.LDAPEntry(client=None,
                                     dn=self.dn,
                                     attributes=self.data,
                                     complete=1)
            self.dn = None
            self.data = None
            self.completed(o)
            return

        key, val = self._parseLine(line)

        if not key in self.data:
            self.data[key] = []

        self.data[key].append(val)

    def completed(self, obj):
        pass
