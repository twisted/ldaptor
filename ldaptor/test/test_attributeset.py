"""
Test cases for ldaptor.attributeset
"""
from functools import total_ordering

from twisted.trial import unittest
from ldaptor import attributeset


class TestLDAPAttributeSet(unittest.TestCase):
    """
    Unit tests for LDAPAttributeSet.
    """
    def testEquality_True_Set(self):
        """
        Attributes are equal when the have the same key and value.
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        self.assertEqual(a, b)

    def testEquality_True_Set_Ordering(self):
        """
        The order of the element in the value doesn't matter for
        equality.
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'd', 'c'])
        self.assertEqual(a, b)

    def testEquality_True_List(self):
        """
        It can be compared with a list and in this case the key is
        ignored.
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = ['b', 'c', 'd']
        self.assertEqual(a, b)

    def testEquality_True_List_Ordering(self):
        """
        For list comparison the order of the element don't matter.
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = ['b', 'd', 'c']
        self.assertEqual(a, b)

    def testEquality_False_Value(self):
        """
        LDAPAttributeSet objects are not equal when they have
        different values.
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertNotEqual(a, b)

    def testEquality_False_Key(self):
        """
        Equality fails if attributes have different keys.
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('l', ['b', 'c', 'd'])
        self.assertNotEqual(a, b)

    def testDifference(self):
        """
        Different operation will ignore the attribute's key and will
        perform the operation onlyb based on the attribute's value.
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('l', ['b', 'c', 'e'])

        result = a - b

        self.assertEqual({'d'}, result)

    def testAddNewValue(self):
        """
        Adding new value
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        a.add('e')

        self.assertEqual(a, {'b', 'c', 'd', 'e'})

    def testAddExistingValue(self):
        """
        Adding existing value as a byte or unicode string
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])

        a.add(b'b')
        self.assertEqual(a, {'b', 'c', 'd'})

        a.add(u'b')
        self.assertEqual(a, {'b', 'c', 'd'})

    def testRemoveExistingValue(self):
        """
        Removing existing value as a byte or unicode string
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        a.remove(b'b')
        a.remove(u'c')

        self.assertEqual(a, {'d'})

    def testRemoveNonexistingValue(self):
        """
        Removing non-existing value
        """
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])

        self.assertRaises(KeyError, a.remove, 'e')

    def testUnion(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertEqual(a | b, {'b', 'c', 'd', 'e'})

    def testIntersection(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertEqual(a & b, {'b', 'c'})

    def testSymmetricDifference(self):
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd'])
        b = attributeset.LDAPAttributeSet('k', ['b', 'c', 'e'])
        self.assertEqual(a ^ b, {'d', 'e'})

    def testCopy(self):
        class Magic:
            def __lt__(self, other):
                return False

            def __gt__(self, other):
                return True

        m1 = Magic()
        a = attributeset.LDAPAttributeSet('k', ['b', 'c', 'd', m1])
        b = a.__copy__()
        self.assertEqual(a, b)
        self.assertNotIdentical(a, b)

        magicFromA = [val for val in a if isinstance(val, Magic)][0]
        magicFromB = [val for val in b if isinstance(val, Magic)][0]
        self.assertEqual(magicFromA, magicFromB)
        self.assertIdentical(magicFromA, magicFromB)

        a.update('x')
        self.assertEqual(a, {'b', 'c', 'd', m1, 'x'})
        self.assertEqual(b, {'b', 'c', 'd', m1})

    def testDeepCopy(self):
        @total_ordering
        class Magic:
            def __eq__(self, other):
                return isinstance(other, self.__class__)

            def __hash__(self):
                return 42

            def __lt__(self, other):
                return False


        m1 = Magic()
        a = attributeset.LDAPAttributeSet('k', ['a', m1])
        b = a.__deepcopy__({})
        self.assertEqual(a, b)
        self.assertNotIdentical(a, b)

        magicFromA = [val for val in a if isinstance(val, Magic)][0]
        magicFromB = [val for val in b if isinstance(val, Magic)][0]
        self.assertEqual(magicFromA, magicFromB)
        self.assertNotIdentical(magicFromA, magicFromB)

        a.update('x')
        self.assertEqual(a, {'a', m1, 'x'})
        self.assertEqual(b, {'a', m1})
