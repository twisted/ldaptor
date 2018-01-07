import warnings

import string
try:
    maketrans = string.maketrans
except AttributeError:
    maketrans = bytes.maketrans

import six

from ldaptor import md4, config

lower = b'abcdefghijklmnopqrstuvwxyz'
upper = lower.upper()
toupper= maketrans(lower, upper)

def nthash(password=b''):
    """Generates nt md4 password hash for a given password."""

    password = password[:128]
    password = ''.join([c + '\000' for c in password])
    return md4.new(password).hexdigest().translate(toupper);


def lmhash_locked(password=b''):
    """
    Generates a lanman password hash that matches no password.

    Note that the author thinks LanMan hashes should be banished from
    the face of the earth.
    """
    return 32 * b'X'


def _no_lmhash(password=''):
    if config.useLMhash():
        warnings.warn("Cannot import Crypto.Cipher.DES, lmhash passwords disabled.")
    return lmhash_locked()


def _have_lmhash(password=''):
    """
    Generates lanman password hash for a given password.

    Note that the author thinks LanMan hashes should be banished from
    the face of the earth.
    """

    if not config.useLMhash():
        return lmhash_locked()

    password = (password + 14 * b'\0')[:14]
    password = password.upper()

    return _deshash(password[:7]) + _deshash(password[7:])


try:
    from Crypto.Cipher import DES
except ImportError:
    lmhash = _no_lmhash
else:
    lmhash = _have_lmhash

LM_MAGIC = "KGS!@#$%"


def _deshash(p):
    # Insert parity bits. I'm not going to bother myself with smart
    # implementations.
    bits = []
    for byte in [six.byte2int([c]) for c in p]:
        bits.extend([bool(byte & 128),
                     bool(byte & 64),
                     bool(byte & 32),
                     bool(byte & 16),
                     bool(byte & 8),
                     bool(byte & 4),
                     bool(byte & 2),
                     bool(byte & 1)])

    def _pack(bits):
        x = ((bits[0] << 7)
             + (bits[1] << 6)
             + (bits[2] << 5)
             + (bits[3] << 4)
             + (bits[4] << 3)
             + (bits[5] << 2)
             + (bits[6] << 1))
        return x

    bytes = (_pack(bits[:7]),
             _pack(bits[7:14]),
             _pack(bits[14:21]),
             _pack(bits[21:28]),
             _pack(bits[28:35]),
             _pack(bits[35:42]),
             _pack(bits[42:49]),
             _pack(bits[49:]))
    bytes = ''.join([chr(x) for x in bytes])
    cipher = DES.new(bytes, DES.MODE_ECB)
    raw = cipher.encrypt(LM_MAGIC)
    l = ['%02X' % six.byte2int([x]) for x in raw]
    return ''.join(l)
