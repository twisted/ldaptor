"""
Test cases for the ldaptor.samba.smbpassword module.
"""

from twisted.trial import unittest
from ldaptor.samba import smbpassword
import types

class LDAPSmbPassword(unittest.TestCase):
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
