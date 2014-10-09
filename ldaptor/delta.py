"""
Changes to the content of one single LDAP entry.

(This means these do not belong here: adding or deleting of entries,
changing of location in tree)
"""

from ldaptor import attributeset
from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import ldif, distinguishedname
class Modification(attributeset.LDAPAttributeSet):
    def patch(self, entry):
        raise NotImplementedError

    _LDAP_OP = None

    def asLDAP(self):
        if self._LDAP_OP is None:
            raise NotImplementedError("%s.asLDAP not implemented"
                                      % self.__class__.__name__)
        tmplist = list(self)
        newlist = []
        for x in range(len(tmplist)):
            if (isinstance(tmplist[x], unicode)):
                value = tmplist[x].encode('utf-8')
                newlist.append(value)
            else:
                value = tmplist[x]
                newlist.append(value) 
        
        return str(pureber.BERSequence([
            pureber.BEREnumerated(self._LDAP_OP),
            pureber.BERSequence([ pureldap.LDAPAttributeDescription(self.key),
                                  pureber.BERSet(map(pureldap.LDAPString, newlist)),
                                  ]),
            ]))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return super(Modification, self).__eq__(other)

class Add(Modification):
    _LDAP_OP = 0

    def patch(self, entry):
        if self.key in entry:
            entry[self.key].update(self)
        else:
            entry[self.key] = self

    def asLDIF(self):
        r=[]
        values = list(self)
        values.sort()
        r.append(ldif.attributeAsLDIF('add', self.key))
        for v in values:
            r.append(ldif.attributeAsLDIF(self.key, v))
        r.append('-\n')
        return ''.join(r)

class Delete(Modification):
    _LDAP_OP = 1

    def patch(self, entry):
        if not self:
            del entry[self.key]
        else:
            for v in self:
                entry[self.key].remove(v)

    def asLDIF(self):
        r=[]
        values = list(self)
        values.sort()
        r.append(ldif.attributeAsLDIF('delete', self.key))
        for v in values:
            r.append(ldif.attributeAsLDIF(self.key, v))
        r.append('-\n')
        return ''.join(r)

class Replace(Modification):
    _LDAP_OP = 2

    def patch(self, entry):
        if self:
            entry[self.key] = self
        else:
            try:
                del entry[self.key]
            except KeyError:
                pass

    def asLDIF(self):
        r=[]
        values = list(self)
        values.sort()
        r.append(ldif.attributeAsLDIF('replace', self.key))
        for v in values:
            r.append(ldif.attributeAsLDIF(self.key, v))
        r.append('-\n')
        return ''.join(r)


class Operation(object):
    def patch(self, root):
        """
        Find the correct entry in IConnectedLDAPEntry and patch it.

        @param root: IConnectedLDAPEntry that is at the root of the
        subtree the patch applies to.

        @returns: Deferred with None or failure.
        """
        raise NotImplementedError

class ModifyOp(Operation):
    def __init__(self, dn, modifications=[]):
        if not isinstance(dn, distinguishedname.DistinguishedName):
            dn=distinguishedname.DistinguishedName(stringValue=dn)
        self.dn = dn
        self.modifications = modifications[:]

    def asLDIF(self):
        r = []
        r.append(ldif.attributeAsLDIF('dn', str(self.dn)))
        r.append(ldif.attributeAsLDIF('changetype', 'modify'))
        for m in self.modifications:
            r.append(m.asLDIF())
        r.append("\n")
        return ''.join(r)

    def asLDAP(self):
        return pureldap.LDAPModifyRequest(
            object=str(self.dn),
            modification=[x.asLDAP() for x in self.modifications])

    def _getClassFromOp(class_, op):
        for mod in [Add, Delete, Replace]:
            if op == mod._LDAP_OP:
                return mod
        return None
    _getClassFromOp = classmethod(_getClassFromOp)

    def fromLDAP(class_, request):
        if not isinstance(request, pureldap.LDAPModifyRequest):
            raise RuntimeError("%s.fromLDAP needs an LDAPModifyRequest"
                               % class_.__name__)
        dn = request.object
        result = []
        for op, mods in request.modification:
            op = op.value
            klass = class_._getClassFromOp(op)
            if klass is None:
                raise RuntimeError("Unknown LDAP op number %r in %s.fromLDAP"
                                   % (op, class_.__name__))

            key, vals = mods
            key = key.value
            vals = [x.value for x in vals]
            m = klass(key, vals)
            result.append(m)
        return class_(dn, result)
    fromLDAP = classmethod(fromLDAP)

    def patch(self, root):
        d = root.lookup(self.dn)
        def gotEntry(entry, modifications):
            for mod in self.modifications:
                mod.patch(entry)
            return entry
        d.addCallback(gotEntry, self.modifications)
        return d

    def __repr__(self):
        return (self.__class__.__name__
                + '('
                + 'dn=%r' % str(self.dn)
                + ', '
                + 'modifications=%r' % self.modifications
                + ')')

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return 0
        if self.dn != other.dn:
            return 0
        if self.modifications != other.modifications:
            return 0
        return 1

    def __ne__(self, other):
        return not self==other

class AddOp(Operation):
    def __init__(self, entry):
        self.entry = entry

    def asLDIF(self):
        l = str(self.entry).splitlines()
        assert l[0].startswith('dn:')
        l[1:1] = [ldif.attributeAsLDIF('changetype', 'add').rstrip('\n')]
        return ''.join([x+'\n' for x in l])

    def patch(self, root):
        d = root.lookup(self.entry.dn.up())
        def gotParent(parent, entry):
            parent.addChild(entry.dn.split()[0], entry)
        d.addCallback(gotParent, self.entry)
        return d

    def __repr__(self):
        return (self.__class__.__name__
                + '('
                + '%r' % self.entry
                + ')')

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if self.entry != other.entry:
            return False
        return True

    def __ne__(self, other):
        return not self==other

class DeleteOp(Operation):
    def __init__(self, dn):
        self.dn = dn

    def asLDIF(self):
        r = []
        r.append(ldif.attributeAsLDIF('dn', str(self.dn)))
        r.append(ldif.attributeAsLDIF('changetype', 'delete'))
        r.append("\n")
        return ''.join(r)

    def patch(self, root):
        d = root.lookup(self.dn)
        def gotEntry(entry):
            return entry.delete()
        d.addCallback(gotEntry)
        return d

    def __repr__(self):
        return (self.__class__.__name__
                + '('
                + '%r' % self.dn
                + ')')

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if self.dn != other.dn:
            return False
        return True

    def __ne__(self, other):
        return not self==other

