import sys
from ldaptor.protocols.ldap import ldif
from ldaptor import usage, inmemory
from twisted.internet import reactor

exitStatus = 0


def error(fail):
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


def output(result, outputFile):
    outputFile.write(ldif.header())
    for op in result:
        outputFile.write(op.asLDIF())


def main(filename1, filename2, outputFile):
    def _open(filename):
        f = open(filename)
        d = inmemory.fromLDIFFile(f)
        return d

    d = _open(filename1)

    def _gotDB1(db1, filename2):
        d = _open(filename2)
        d.addCallback(lambda db2: db1.diffTree(db2))
        return d

    d.addCallback(_gotDB1, filename2)

    d.addCallback(output, outputFile)
    d.addErrback(error)
    d.addBoth(lambda x: reactor.callWhenRunning(reactor.stop))

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(usage.Options, usage.Options_service_location, usage.Options_bind):
    """LDAPtor object rename utility"""

    def parseArgs(self, file1, file2):
        self.opts["file1"] = file1
        self.opts["file2"] = file2


def console_script():
    try:
        config = MyOptions()
        config.parseOptions()
    except usage.UsageError as ue:
        sys.stderr.write("{}: {}\n".format(sys.argv[0], ue))
        sys.exit(1)

    main(config.opts["file1"], config.opts["file2"], sys.stdout)


if __name__ == "__main__":
    sys.exit(console_script())
