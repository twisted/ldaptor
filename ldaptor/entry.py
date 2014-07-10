import random, base64
from zope.interface import implements
from twisted.internet import defer
from twisted.python.util import InsensitiveDict
from ldaptor import interfaces, attributeset, delta
from ldaptor.protocols.ldap import distinguishedname, ldif, ldaperrors

try:
    from hashlib import sha1
except ImportError:
    from sha import sha as sha1


def sshaDigest(passphrase, salt=None):
    if salt is None:
        salt = ''
        for i in range(8):
            salt += chr(random.randint(0, 255))

    s = sha1()
    s.update(passphrase)
    s.update(salt)
    encoded = base64.encodestring(s.digest()+salt).rstrip()
    crypt = '{SSHA}' + encoded
    return crypt

class BaseLDAPEntry(object):
    implements(interfaces.ILDAPEntry)
    dn = None

    def __init__(self, dn, attributes={}):
        """

        Initialize the object.

        @param dn: Distinguished Name of the object, as a string.

        @param attributes: Attributes of the object. A dictionary of
        attribute types to list of attribute values.

        """
        self._attributes=InsensitiveDict()
        self.dn = distinguishedname.DistinguishedName(dn)

        for k,vs in attributes.items():
            if k not in self._attributes:
                self._attributes[k] = []
            self._attributes[k].extend(vs)

        for k,vs in self._attributes.items():
            self._attributes[k] = self.buildAttributeSet(k, vs)

    def buildAttributeSet(self, key, values):
        return attributeset.LDAPAttributeSet(key, values)

    def __getitem__(self, key):
        return self._attributes[key]

    def get(self, key, default=None):
        return self._attributes.get(key, default)

    def has_key(self, key):
        return key in self._attributes

    def __contains__(self, key):
        return self.has_key(key)

    def keys(self):
        return self._attributes.keys()

    def items(self):
        return self._attributes.items()

    def __str__(self):
        a=[]

        objectClasses = list(self.get('objectClass', []))
        objectClasses.sort()
        a.append(('objectClass', objectClasses))

        l=list(self.items())
        l.sort()
        for key, values in l:
            if key.lower() != 'objectclass':
                vs = list(values)
                vs.sort()
                a.append((key, vs))
        return ldif.asLDIF(self.dn, a)

    def __eq__(self, other):
        if not isinstance(other, BaseLDAPEntry):
            return 0
        if self.dn != other.dn:
            return 0

        my=[key for key in self.keys() if key != 'objectClass']
        my.sort()
        its=[key for key in other.keys() if key != 'objectClass']
        its.sort()
        if my!=its:
            return 0
        for key in my:
            myAttr=self[key]
            itsAttr=other[key]
            if myAttr!=itsAttr:
                return 0

        myObjectClass = list(self.get('objectClass', []))
        myObjectClass.sort()
        itsObjectClass = list(its.get('objectClass', []))
        itsObjectClass.sort()

        if myObjectClass == itsObjectClass:
            return 0
        
        return 1

    def __ne__(self, other):
        return not self==other

    def __len__(self):
        return len(self.keys())

    def __nonzero__(self):
        return True

    def __repr__(self):
        x={}
        for key in self.keys():
            x[key]=self[key]
        keys=self.keys()
        keys.sort()
        a=[]
        for key in keys:
            a.append('%s: %s' % (repr(key), repr(list(self[key]))))
        attributes=', '.join(a)
        return '%s(%s, {%s})' % (
            self.__class__.__name__,
            repr(str(self.dn)),
            attributes)

    def diff(self, other):
        """
        Compute differences between this and another LDAP entry.

        @param other: An LDAPEntry to compare to.

        @return: None if equal, otherwise a ModifyOp that would make
        this entry look like other.
        """
        assert self.dn == other.dn
        if self == other:
            return None

        r = []

        myKeys = set(self.keys())
        otherKeys = set(other.keys())

        addedKeys = list(otherKeys - myKeys)
        addedKeys.sort() # for reproducability only
        for added in addedKeys:
            r.append(delta.Add(added, other[added]))

        deletedKeys = list(myKeys - otherKeys)
        deletedKeys.sort() # for reproducability only
        for deleted in deletedKeys:
            r.append(delta.Delete(deleted, self[deleted]))

        sharedKeys = list(myKeys & otherKeys)
        sharedKeys.sort() # for reproducability only
        for shared in sharedKeys:

            addedValues = list(other[shared] - self[shared])
            if addedValues:
                addedValues.sort() # for reproducability only
                r.append(delta.Add(shared, addedValues))

            deletedValues = list(self[shared] - other[shared])
            if deletedValues:
                deletedValues.sort() # for reproducability only
                r.append(delta.Delete(shared, deletedValues))

        return delta.ModifyOp(dn=self.dn, modifications=r)

    def bind(self, password):
        return defer.maybeDeferred(self._bind, password)

    def _bind(self, password):
        for digest in self.get('userPassword', ()):
            if digest.startswith('{SSHA}'):
                raw = base64.decodestring(digest[len('{SSHA}'):])
                salt = raw[20:]
                got = sshaDigest(password, salt)
                if got == digest:
                    return self
        raise ldaperrors.LDAPInvalidCredentials

    def hasMember(self, dn):
        for memberDN in self.get('member', []):
            if memberDN == dn:
                return True
        return False

    def __hash__(self):
        return hash(self.dn)

class EditableLDAPEntry(BaseLDAPEntry):
    implements(interfaces.IEditableLDAPEntry)

    def __setitem__(self, key, value):
        new=self.buildAttributeSet(key, value)
        self._attributes[key] = new

    def __delitem__(self, key):
        del self._attributes[key]

    def undo(self):
        raise NotImplementedError

    def commit(self):
        raise NotImplementedError

    def move(self, newDN):
        raise NotImplementedError

    def delete(self):
        raise NotImplementedError

    def setPassword(self, newPasswd, salt=None):
        crypt = sshaDigest(newPasswd, salt)
        self['userPassword'] = [crypt]
