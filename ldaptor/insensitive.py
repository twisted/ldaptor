class InsensitiveString(str):
    """A str subclass that performs all matching without regard to case."""

    def __eq__(self, other):
        if isinstance(other, basestring):
            return self.lower() == other.lower()
        else:
            return super(InsensitiveString, self).__eq__(other)

    def __ne__(self, other):
        if isinstance(other, basestring):
            return self.lower() != other.lower()
        else:
            return super(InsensitiveString, self).__ne__(self, other)

    def __ge__(self, other):
        if isinstance(other, basestring):
            return self.lower() >= other.lower()
        else:
            return super(InsensitiveString, self).__ge__(self, other)

    def __gt__(self, other):
        if isinstance(other, basestring):
            return self.lower() > other.lower()
        else:
            return super(InsensitiveString, self).__gt__(self, other)

    def __le__(self, other):
        if isinstance(other, basestring):
            return self.lower() <= other.lower()
        else:
            return super(InsensitiveString, self).__le__(self, other)

    def __lt__(self, other):
        if isinstance(other, basestring):
            return self.lower() < other.lower()
        else:
            return super(InsensitiveString, self).__lt__(self, other)

    def __hash__(self):
        return hash(self.lower())

    def __contains__(self, other):
        if isinstance(other, basestring):
            return other.lower() in self.lower()
        else:
            return super(InsensitiveString, self).__contains__(self, other)

    def __getslice__(self, *a, **kw):
        r = super(InsensitiveString, self).__getslice__(*a, **kw)
        return self.__class__(r)
