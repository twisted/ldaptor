# Twisted, the Framework of Your Internet
# Copyright (C) 2001 Matthew W. Lefkowitz
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

from bidirdict import BidirDict

def get(resultCode, errorMessage):
    """Get an instance of the correct exception for this resultCode."""
    #TODO
    return LDAPUnknownError(resultCode, errorMessage)

class LDAPException(Exception):
    resultCode=None

class LDAPOperationsError(LDAPException):
    resultCode=1

class LDAPProtocolError(LDAPException):
    resultCode=2

class LDAPUnknownError(LDAPException):
    resultCode=None

    def __str__(self):
        code=self.args[0]
        codeName=errors.reverse[code] or 'unknownError(%d)'%code
        message=self.args[1]
        if message:
            return '%s: %s' % (codeName, message)
        else:
            return codeName

errors = BidirDict(
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
