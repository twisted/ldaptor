#!/usr/bin/python
import unittest, os, os.path, sys

def getTestDir():
    import sys
    if sys.argv[0]:
        file=sys.argv[0]
    else:
        import all
        file=all.__file__
    return os.path.dirname(file)

def getTestSuites():
    dir=getTestDir()
    modules_to_test = [x[:-len(".py")] for x in os.listdir(dir)
                       if (x.startswith("test_")
                           and x.endswith(".py"))]
    alltests = unittest.TestSuite()
    for module in map(__import__, modules_to_test):
        alltests.addTest(unittest.findTestCases(module))
    return alltests

if __name__ == '__main__':
    unittest.main(defaultTest='getTestSuites')
