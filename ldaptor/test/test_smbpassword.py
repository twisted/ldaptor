"""
Test cases for the ldaptor.samba.smbpassword module.
"""

from twisted.trial import unittest
from ldaptor.samba import smbpassword
from ldaptor import config

class TestNTHash(unittest.TestCase):
    knownValues=( # password, expected_result
        ('', '31D6CFE0D16AE931B73C59D7E0C089C0'),
        ('foo', 'AC8E657F83DF82BEEA5D43BDAF7800CC'),
        (127*'x', '25900FAB94A048BCF438615217776562'),
        (128*'x', '65681023D0CB5E7E96FF662150EF060D'),
        (129*'x', '65681023D0CB5E7E96FF662150EF060D'),
        (1000*'x', '65681023D0CB5E7E96FF662150EF060D'),
        )

    def testKnownValues(self):
        """nthash(...) gives known results"""
        for password, expected_result in self.knownValues:
            result = smbpassword.nthash(password)
            if result != expected_result:
                raise AssertionError, 'nthash(%s)=%s, expected %s' \
                      % (repr(password), repr(result), repr(expected_result))

class TestLMHash(unittest.TestCase):
    knownValues=( # password, expected_result
        ('', 'AAD3B435B51404EEAAD3B435B51404EE'),
        ('foo', '5BFAFBEBFB6A0942AAD3B435B51404EE'),
        (13*'x', '3AA62DBBEFDB676366B4159AF5A7C45C'),
        (14*'x', '3AA62DBBEFDB67633AA62DBBEFDB6763'),
        (15*'x', '3AA62DBBEFDB67633AA62DBBEFDB6763'),
        (100*'x', '3AA62DBBEFDB67633AA62DBBEFDB6763'),
        ('1234567abcdefg', '0182BD0BD4444BF8E0C510199CC66ABD'),
        ('XXXXXXXabcdefg', '3AA62DBBEFDB6763E0C510199CC66ABD'),
        ('1234567XXXXXXX', '0182BD0BD4444BF83AA62DBBEFDB6763'),
        )

    def testKnownValues(self):
        """lmhash(...) gives known results"""
        cfg = config.loadConfig()
        for password, expected_result in self.knownValues:
            cfg.set('samba', 'use-lmhash', 'no')
            disabled = smbpassword.lmhash(password)
            self.assertEquals(disabled, 32*'X',
                              "Disabled lmhash must be X's: %r" % disabled)

            cfg.set('samba', 'use-lmhash', 'yes')
            result = smbpassword.lmhash(password)
            if result != expected_result:
                raise AssertionError, 'lmhash(%s)=%s, expected %s' \
                      % (repr(password), repr(result), repr(expected_result))
