import sets
from twisted.internet import defer
from ldaptor import delta

class DiffTreeMixin(object):
    def _diffTree_gotMyChildren(self, myChildren, other, result):
        d = other.children()
        d.addCallback(self._diffTree_gotBothChildren, myChildren, other, result)
        return d

    def _diffTree_gotBothChildren(self,
                                  otherChildren,
                                  myChildren,
                                  other,
                                  result):
        def rdnToChild(rdn, l):
            r = [x for x in l if x.dn.split()[0] == rdn]
            assert len(r) == 1
            return r[0]

        my = sets.Set([x.dn.split()[0] for x in myChildren])
        his = sets.Set([x.dn.split()[0] for x in otherChildren])

        # differences in common children
        commonRDN = list(my & his)
        commonRDN.sort() # for reproducability only
        d = self._diffTree_commonChildren([
            (rdnToChild(rdn, myChildren), rdnToChild(rdn, otherChildren))
            for rdn in commonRDN
            ], result)

        # added children
        addedRDN = list(his - my)
        addedRDN.sort() # for reproducability only
        d2 = self._diffTree_addedChildren([
            rdnToChild(rdn, otherChildren)
            for rdn in addedRDN
            ], result)
        d.addCallback(lambda _: d2)

        # deleted children
        deletedRDN = list(my - his)
        deletedRDN.sort() # for reproducability only
        d3 = self._diffTree_deletedChildren([
            rdnToChild(rdn, myChildren)
            for rdn in deletedRDN
            ], result)
        d.addCallback(lambda _: d3)

        return d

    def _diffTree_commonChildren(self, children, result):
        if not children:
            return defer.succeed(result)
        first, rest = children[0], children[1:]
        a, b = first
        d = a.diffTree(b, result)
        d.addCallback(lambda _: self._diffTree_commonChildren(rest, result))
        return d

    def _diffTree_addedChildren(self, children, result):
        if not children:
            return result
        first, rest = children[0], children[1:]

        d = first.subtree()
        def _gotSubtree(l, result):
            for c in l:
                o = delta.AddOp(c)
                result.append(o)
            return result
        d.addCallback(_gotSubtree, result)

        d.addCallback(lambda _: self._diffTree_addedChildren(rest, result))
        return d

    def _diffTree_deletedChildren(self, children, result):
        if not children:
            return result
        first, rest = children[0], children[1:]

        d = first.subtree()
        def _gotSubtree(l, result):
            l.reverse() # remove children before their parent
            for c in l:
                o = delta.DeleteOp(c)
                result.append(o)
            return result
        d.addCallback(_gotSubtree, result)

        d.addCallback(lambda _: self._diffTree_deletedChildren(rest, result))
        return d

    def diffTree(self, other, result=None):
        assert self.dn == other.dn, \
               ("diffTree arguments must refer to same LDAP tree:"
                "%r != %r" % (str(self.dn), str(other.dn))
                )
        if result is None:
            result = []

        # differences in root
        rootDiff = self.diff(other)
        if rootDiff is not None:
            result.append(rootDiff)

        d = self.children()
        d.addCallback(self._diffTree_gotMyChildren, other, result)

        return d

class SubtreeFromChildrenMixin(object):
    def subtree(self, callback=None):
        if callback is None:
            result = []
            d = self.subtree(callback=result.append)
            d.addCallback(lambda _: result)
            return d
        else:
            callback(self)
            d = self.children()
            def _processOneChild(_, children, callback):
                if not children:
                    return None

                c = children.pop()
                d = c.subtree(callback)
                d.addCallback(_processOneChild, children, callback)
            def _gotChildren(children, callback):
                _processOneChild(None, children, callback)
            d.addCallback(_gotChildren, callback)
            return d
