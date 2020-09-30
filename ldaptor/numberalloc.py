"""Find an available uidNumber/gidNumber/other similar number."""

from ldaptor.protocols import pureldap

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

        guess = (max + self.min) // 2
        d=self.makeAGuess(guess)
        d.addCallback(self._nextGuess, guess)
        return d

class ldapGuesser:
    def __init__(self, ldapObject, numberType):
        self.numberType=numberType
        self.ldapObject=ldapObject

    def guess(self, num):
        d=self.ldapObject.search(
            filterObject=pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription(value=self.numberType),
            assertionValue=pureldap.LDAPAssertionValue(value=str(num))),
            sizeLimit=1)
        d.addCallback(lambda results: len(results))
        return d

def getFreeNumber(ldapObject, numberType, min=None, max=None):
    g=freeNumberGuesser(ldapGuesser(ldapObject, numberType).guess,
                        min=min, max=max)
    return g.startGuessing()
