from copy import deepcopy


class LDAPAttributeSet(set):
    def __init__(self, key, *a, **kw):
        """
        Represents all the values for an attribute in an LDAP entry. An entry
        might have "cn" or "objectClass" or "uid" attributes, and this class
        represents each of those.

        You can find the name of the LDAP entry attribute (eg. "uid") with the
        ``.key`` member variable.

        You can find the values of the LDAP attribute by casting this to a
        ``list``.
        @param key: the key of the attribute, eg "uid".
        @type key: str
        @param args: set of values for this attribute, eg. "jsmith"
        """
        self.key = key
        super(LDAPAttributeSet, self).__init__(*a, **kw)

    def __repr__(self):
        values = list(self)
        values.sort()
        attributes = ', '.join([repr(x) for x in values])
        return '%s(%r, [%s])' % (
            self.__class__.__name__,
            self.key,
            attributes)

    def __eq__(self, other):
        """
        Note that LDAPAttributeSets can also be compared against any
        iterator. In that case the attributeType will be ignored.
        """
        if isinstance(other, LDAPAttributeSet):
            if self.key != other.key:
                return False
            return super(LDAPAttributeSet, self).__eq__(other)
        else:
            me = list(self)
            me.sort()
            him = list(other)
            him.sort()
            return me == him

    def __ne__(self, other):
        return not self == other

    def copy(self):
        result = self.__class__(self.key)
        result.update(self)
        return result

    __copy__ = copy

    def __deepcopy__(self, memo):
        result = self.__class__(self.key)
        memo[id(self)] = result
        data = deepcopy(set(self), memo)
        result.update(data)
        return result
