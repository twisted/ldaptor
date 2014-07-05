from copy import deepcopy

class LDAPAttributeSet(set):
    def __init__(self, key, *a, **kw):
        self.key = key
        super(LDAPAttributeSet, self).__init__(*a, **kw)

    def __repr__(self):
        values=list(self)
        values.sort()
        attributes=', '.join([repr(x) for x in values])
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
            me=list(self)
            me.sort()
            him=list(other)
            him.sort()
            return me == him

    def __ne__(self, other):
        return not self==other

    def difference(self, other):
        return set(self) - set(other)

    def union(self, other):
        return set(self) | set(other)

    def intersection(self, other):
        return set(self) & set(other)

    def symmetric_difference(self, other):
        return set(self) ^ set(other)

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
