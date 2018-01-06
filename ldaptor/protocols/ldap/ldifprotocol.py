import base64

from twisted.protocols import basic
from twisted.internet import protocol

from ldaptor import entry

class LDIFParseError(Exception):
    """Error parsing LDIF."""

    def __str__(self):
        s = self.__doc__
        if self.args:
            s = ': '.join([s] + list(map(str, self.args)))
        return s + '.'


class LDIFLineWithoutSemicolonError(LDIFParseError):
    """LDIF line without semicolon seen"""
    pass


class LDIFEntryStartsWithNonDNError(LDIFParseError):
    """LDIF entry starts with a non-DN line"""
    pass


class LDIFEntryStartsWithSpaceError(LDIFParseError):
    """Invalid LDIF value format"""
    pass


class LDIFVersionNotANumberError(LDIFParseError):
    """Non-numeric LDIF version number"""
    pass


class LDIFUnsupportedVersionError(LDIFParseError):
    """LDIF version not supported"""
    pass


class LDIFTruncatedError(LDIFParseError):
    """LDIF appears to be truncated"""
    pass


HEADER = 'HEADER'
WAIT_FOR_DN = 'WAIT_FOR_DN'
IN_ENTRY = 'IN_ENTRY'

class LDIF(basic.LineReceiver, object):
    delimiter = b'\n'
    mode = HEADER

    dn = None
    data = None
    lastLine = None

    version = None

    def logicalLineReceived(self, line):
        if line.startswith(b'#'):
            # comments are allowed everywhere
            return
        getattr(self, 'state_' + self.mode)(line)

    def lineReceived(self, line):
        if line.startswith(b' '):
            if self.lastLine is None:
                raise LDIFEntryStartsWithSpaceError()
            self.lastLine = self.lastLine + line[1:]
        else:
            if self.lastLine is not None:
                self.logicalLineReceived(self.lastLine)
            self.lastLine = line
            if line == b'':
                self.logicalLineReceived(line)
                self.lastLine = None

    def parseValue(self, val):
        if val.startswith(b':'):
            return base64.decodestring(val[1:].lstrip(b' '))
        elif val.startswith(b'<'):
            raise NotImplementedError()
        else:
            return val.lstrip(b' ')

    def _parseLine(self, line):
        try:
            key, val = line.split(b':', 1)
        except ValueError:
            # unpack list of wrong size
            # -> invalid input data
            raise LDIFLineWithoutSemicolonError(line)
        val = self.parseValue(val)
        return key, val

    def state_HEADER(self, line):
        key, val = self._parseLine(line)
        self.mode = WAIT_FOR_DN

        if key != b'version':
            self.logicalLineReceived(line)
        else:
            try:
                version = int(val)
            except ValueError:
                raise LDIFVersionNotANumberError(val)
            self.version = version
            if version > 1:
                raise LDIFUnsupportedVersionError(version)

    def state_WAIT_FOR_DN(self, line):
        assert self.dn is None, 'self.dn must not be set when waiting for DN'
        assert self.data is None, 'self.data must not be set when waiting for DN'
        if line == b'':
            # too many empty lines, but be tolerant
            return

        key, val = self._parseLine(line)

        if key.upper() != b'DN':
            raise LDIFEntryStartsWithNonDNError(line)

        self.dn = val
        self.data = {}
        self.mode = IN_ENTRY

    def state_IN_ENTRY(self, line):
        assert self.dn is not None, 'self.dn must be set when in entry'
        assert self.data is not None, 'self.data must be set when in entry'

        if line == b'':
            # end of entry
            self.mode = WAIT_FOR_DN
            o = entry.BaseLDAPEntry(dn=self.dn,
                                    attributes=self.data)
            self.dn = None
            self.data = None
            self.gotEntry(o)
            return

        key, val = self._parseLine(line)

        if not key in self.data:
            self.data[key] = []

        self.data[key].append(val)

    def gotEntry(self, obj):
        pass

    def connectionLost(self, reason=protocol.connectionDone):
        if self.mode != WAIT_FOR_DN:
            raise LDIFTruncatedError(reason)
