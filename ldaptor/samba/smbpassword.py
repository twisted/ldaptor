from passlib.hash import (nthash as passlib_nthash, lmhash as passlib_lmhash)

from ldaptor import config

def nthash(password=b''):
    """Generates nt md4 password hash for a given password."""
    return passlib_nthash.hash(password[:128]).encode('ascii').upper()


def lmhash_locked(password=b''):
    """
    Generates a lanman password hash that matches no password.

    Note that the author thinks LanMan hashes should be banished from
    the face of the earth.
    """
    return 32 * b'X'


def lmhash(password=b''):
    """
    Generates lanman password hash for a given password.

    Note that the author thinks LanMan hashes should be banished from
    the face of the earth.
    """

    if not config.useLMhash():
        return lmhash_locked()

    return passlib_lmhash.hash(password).encode('ascii').upper()
