class AutofillException(Exception):
    pass

class ObjectMissingObjectClassException(AutofillException):
    """

    The LDAPEntry is missing an objectClass this autofiller needs to
    operate.

    """
    pass

class Autofill_samba: #TODO baseclass
    def start(self, ldapObject):
        assert 'objectClass' in ldapObject
        if 'sambaAccount' not in ldapObject['objectClass']:
            raise ObjectMissingObjectClassException, ldapObject

        assert 'acctFlags' not in ldapObject
        ldapObject['acctFlags'] = ['[UX         ]']
        assert 'pwdLastSet' not in ldapObject
        ldapObject['pwdLastSet'] = ['0']
        assert 'logonTime' not in ldapObject
        ldapObject['logonTime'] = ['0']
        assert 'logoffTime' not in ldapObject
        ldapObject['logoffTime'] = ['0']
        assert 'pwdCanChange' not in ldapObject
        ldapObject['pwdCanChange'] = ['0']
        assert 'pwdMustChange' not in ldapObject
        ldapObject['pwdMustChange'] = ['0']

    def notify(self, ldapObject, attributeType):

        # rid=2*uid+1000
        if attributeType == 'uidNumber':
            assert 'uidNumber' in ldapObject
            assert len(ldapObject['uidNumber']) == 1
            for uidNumber in ldapObject['uidNumber']:
                uidNumber = int(uidNumber)
                rid = uidNumber*2+1000
                ldapObject['rid'] = [str(rid)]
                return

        # primaryGroupID=2*gid+1001
        if attributeType == 'gidNumber':
            assert 'gidNumber' in ldapObject
            assert len(ldapObject['gidNumber']) == 1
            for gidNumber in ldapObject['gidNumber']:
                gidNumber = int(gidNumber)
                primaryGroupID = gidNumber*2+1001
                ldapObject['primaryGroupID'] = [str(primaryGroupID)]
                return
