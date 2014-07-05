# Copyright (C) 2001 Tommi Virtanen
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# make pyflakes not complain about undefined names
reverse = None
LDAPOther = None

def get(resultCode, errorMessage):
    """Get an instance of the correct exception for this resultCode."""

    klass = reverse.get(resultCode)
    if klass is not None:
        return klass(errorMessage)
    else:
        return LDAPUnknownError(resultCode, errorMessage)

class LDAPResult:
    resultCode=None
    name=None

class Success(LDAPResult):
    resultCode=0
    name='success'

    def __init__(self, msg):
        pass

class LDAPException(Exception, LDAPResult):

    def _get_message(self): return self.__message
    def _set_message(self, value): self.__message = value
    message = property(_get_message, _set_message)

    def __init__(self, message=None):
        Exception.__init__(self)
        self.message=message

    def __str__(self):
        message=self.message
        if message:
            return '%s: %s' % (self.name, message)
        elif self.name:
            return self.name
        else:
            return 'Unknown LDAP error %r' % self

class LDAPUnknownError(LDAPException):
    resultCode=None

    def __init__(self, resultCode, message=None):
        assert resultCode not in reverse, \
               "resultCode %r must be unknown" % resultCode
        self.code=resultCode
        LDAPException.__init__(self, message)

    def __str__(self):
        codeName='unknownError(%d)'%self.code
        if self.message:
            return '%s: %s' % (codeName, self.message)
        else:
            return codeName

import new
def init(**errors):
    global reverse
    reverse = {}
    for name, value in errors.items():
        if value == errors['success']:
            klass = Success
        else:
            classname = 'LDAP'+name[0].upper()+name[1:]
            klass = new.classobj(classname,
                                 (LDAPException,),
                                 { 'resultCode': value,
                                   'name': name,
                                   })
            globals()[classname] = klass
        reverse[value] = klass

init(
    success=0,
    operationsError=1,
    protocolError=2,
    timeLimitExceeded=3,
    sizeLimitExceeded=4,
    compareFalse=5,
    compareTrue=6,
    authMethodNotSupported=7,
    strongAuthRequired=8,
    # 9 reserved
    referral=10 ,
    adminLimitExceeded=11 ,
    unavailableCriticalExtension=12 ,
    confidentialityRequired=13 ,
    saslBindInProgress=14 ,
    noSuchAttribute=16,
    undefinedAttributeType=17,
    inappropriateMatching=18,
    constraintViolation=19,
    attributeOrValueExists=20,
    invalidAttributeSyntax=21,
    # 22-31 unused
    noSuchObject=32,
    aliasProblem=33,
    invalidDNSyntax=34,
    # 35 reserved for undefined isLeaf
    aliasDereferencingProblem=36,
    # 37-47 unused
    inappropriateAuthentication=48,
    invalidCredentials=49,
    insufficientAccessRights=50,
    busy=51,
    unavailable=52,
    unwillingToPerform=53,
    loopDetect=54,
    # 55-63 unused
    namingViolation=64,
    objectClassViolation=65,
    notAllowedOnNonLeaf=66,
    notAllowedOnRDN=67,
    entryAlreadyExists=68,
    objectClassModsProhibited=69,
    # 70 reserved for CLDAP
    affectsMultipleDSAs=71,
    # 72-79 unused
    other=80,
    # 81-90 reserved for APIs
    )

other=LDAPOther.resultCode
