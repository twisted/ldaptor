"""
Test cases for ldaptor.attributeset
"""

from twisted.trial import unittest
import sets
from ldaptor import attributeset

class TestComparison(unittest.TestCase):
    def testEquality_True_Set(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        self.assertEquals(a, b)

    def testEquality_True_Set_Ordering(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'd', 'c'])
        self.assertEquals(a, b)

    def testEquality_True_List(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = ['b', 'c', 'd']
        self.assertEquals(a, b)

    def testEquality_True_List_Ordering(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = ['b', 'd', 'c']
        self.assertEquals(a, b)

    def testEquality_False_Value(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertNotEqual(a, b)

    def testEquality_False_Key(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('l', ['b', 'c', 'd'])
        self.assertNotEqual(a, b)

class TestSetOperations(unittest.TestCase):
    def testDifference(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertEquals(a - b, sets.Set(['d']))

    def testUnion(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertEquals(a | b, sets.Set(['b', 'c', 'd', 'e']))

    def testIntersection(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertEquals(a & b, sets.Set(['b', 'c']))

    def testSymmetricDifference(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertEquals(a ^ b, sets.Set(['d', 'e']))

    def testCopy(self):
        class Magic:
            pass
        m1 = Magic()
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd', m1])
        b = a.__copy__()
        self.assertEquals(a, b)
        self.assertNotIdentical(a, b)

        magicFromA = [val for val in a if isinstance(val, Magic)][0]
        magicFromB = [val for val in b if isinstance(val, Magic)][0]
        self.assertEquals(magicFromA, magicFromB)
        self.assertIdentical(magicFromA, magicFromB)

        a.update('x')
        self.assertEquals(a, sets.Set(['b', 'c', 'd', m1, 'x']))
        self.assertEquals(b, sets.Set(['b', 'c', 'd', m1]))

    def testDeepCopy(self):
        class Magic:
            def __eq__(self, other):
                return isinstance(other, self.__class__)
            def __hash__(self):
                return 42
        m1 = Magic()
        a = attributeset.LDAPAttributeSet('k', ['a', m1])
        b = a.__deepcopy__({})
        self.assertEquals(a, b)
        self.assertNotIdentical(a, b)

        magicFromA = [val for val in a if isinstance(val, Magic)][0]
        magicFromB = [val for val in b if isinstance(val, Magic)][0]
        self.assertEquals(magicFromA, magicFromB)
        self.assertNotIdentical(magicFromA, magicFromB)

        a.update('x')
        self.assertEquals(a, sets.Set(['a', m1, 'x']))
        self.assertEquals(b, sets.Set(['a', m1]))
