"""Find an available uidNumber/gidNumber/other similar number."""

from twisted.internet import defer, reactor
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldapclient

minimum = {
    'uidNumber': 1000,
    'gidNumber': 1000,
    }

class freeNumberGuesser:
    def __init__(self, makeAGuess, min=None, max=None):
        self.makeAGuess=makeAGuess
        self.min=min
        if self.min is None:
            self.min=0
        self.max=max

    def startGuessing(self):
        d=self.makeAGuess(self.min)
        d.addCallback(self._nextGuess, self.min)
        return d

    def _nextGuess(self, found, lastGuess):
        if found:
            self.min=lastGuess
        else:
            self.max=lastGuess

        if self.max==self.min \
           or self.max==self.min+1:
            return self.max

        max=self.max
        if max is None:
            max=self.min+1000

        guess=(max+self.min)/2
        d=self.makeAGuess(guess)
        d.addCallback(self._nextGuess, guess)
        return d

class IsTaken(ldapclient.LDAPSearch):
    def __init__(self, deferred, client, base, numberType, num):
        filt=pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value=numberType),
            assertionValue=pureldap.LDAPAssertionValue(value=str(num)))
        ldapclient.LDAPSearch.__init__(self, deferred, client,
                                       baseObject=base,
                                       filter=filt,
                                       sizeLimit=1,
                                       attributes=[])
        self.found=0
        deferred.addCallback(lambda dummy, self=self: self.found)

    def handle_entry(self, objectName, attributes):
        self.found=1

class ldapGuesser:
    def __init__(self, numberType, ldapClient, baseObject):
        self.numberType=numberType
        self.ldapClient=ldapClient
        self.baseObject=baseObject

    def guess(self, num):
        d=defer.Deferred()
        IsTaken(d, self.ldapClient, self.baseObject, self.numberType, num)
        return d

def getFreeNumber(numberType, ldapClient, baseObject, min=None, max=None):
    g=freeNumberGuesser(ldapGuesser(numberType, ldapClient, baseObject).guess,
                        min=min, max=max)
    return g.startGuessing()
