import sys
from ldaptor.protocols.ldap import ldif, ldifdelta
from ldaptor import usage, inmemory
from twisted.internet import reactor


exitStatus = 0


def error(fail):
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


def output(tree, outputFile):
    outputFile.write(ldif.header())

    def _write(node):
        outputFile.write(str(node))

    tree.subtree(callback=_write)


def main(dataFile, patchFile, outputFile):
    d = inmemory.fromLDIFFile(dataFile)

    def _gotDB(db, patchFile):
        patches = ldifdelta.fromLDIFFile(patchFile)

        # find the right entry to patch
        for p in patches:
            p.patch(db)
        return db

    d.addCallback(_gotDB, patchFile)

    d.addCallback(output, outputFile)
    d.addErrback(error)
    d.addBoth(lambda x: reactor.callWhenRunning(reactor.stop))

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(usage.Options):
    """LDAPtor LDIF patching utility"""

    def parseArgs(self, data):
        self["data"] = data


def console_script():
    try:
        config = MyOptions()
        config.parseOptions()
    except usage.UsageError as ue:
        sys.stderr.write(f"{sys.argv[0]}: {ue}\n")
        sys.exit(1)

    data = open(config["data"])
    main(data, sys.stdin, sys.stdout)


if __name__ == "__main__":
    sys.exit(console_script())
