import string
from ldaptor import md4

lower='abcdefghijklmnopqrstuvwxyz'
upper=lower.upper()
toupper=string.maketrans(lower, upper)

def nthash(password=''):
    """Generates nt md4 password hash for a given password."""

    password=password[:128]
    password=''.join([c+'\000' for c in password])
    return md4.new(password).hexdigest().translate(toupper);

def lmhash(dummy=''):
    """
    Generates lanman password hash for a given password.

    Note that lanman passwords are not supported by Ldaptor and that
    the author thinks they should be banished from the face of the
    earth.

    """
    return 32*'X'
