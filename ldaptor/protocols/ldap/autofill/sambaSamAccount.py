from ldaptor.protocols.ldap.autofill import ObjectMissingObjectClassException

class Autofill_samba: #TODO baseclass
    def start(self, ldapObject):
        assert 'objectClass' in ldapObject
        if 'sambaSamAccount' not in ldapObject['objectClass']:
            raise ObjectMissingObjectClassException, ldapObject

        assert 'sambaAcctFlags' not in ldapObject
        ldapObject['sambaAcctFlags'] = ['[UX         ]']
        assert 'sambaPwdLastSet' not in ldapObject
        ldapObject['sambaPwdLastSet'] = ['0']
        assert 'sambaLogonTime' not in ldapObject
        ldapObject['sambaLogonTime'] = ['0']
        assert 'sambaLogoffTime' not in ldapObject
        ldapObject['sambaLogoffTime'] = ['0']
        assert 'sambaPwdCanChange' not in ldapObject
        ldapObject['sambaPwdCanChange'] = ['0']
        assert 'sambaPwdMustChange' not in ldapObject
        ldapObject['sambaPwdMustChange'] = ['0']

    def notify(self, ldapObject, attributeType):

        # rid=2*uid+1000
##         if attributeType == 'uidNumber':
##             assert 'uidNumber' in ldapObject
##             assert len(ldapObject['uidNumber']) == 1
##             for uidNumber in ldapObject['uidNumber']:
##                 uidNumber = int(uidNumber)
##                 rid = uidNumber*2+1000
##                 ldapObject['rid'] = [str(rid)]
##                 return

        # primaryGroupID=2*gid+1001
##         if attributeType == 'gidNumber':
##             assert 'gidNumber' in ldapObject
##             assert len(ldapObject['gidNumber']) == 1
##             for gidNumber in ldapObject['gidNumber']:
##                 gidNumber = int(gidNumber)
##                 primaryGroupID = gidNumber*2+1001
##                 ldapObject['primaryGroupID'] = [str(primaryGroupID)]
##                 return

        pass
