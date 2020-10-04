import sys, os, getpass
from ldaptor.protocols.ldap import (
    distinguishedname,
    ldapclient,
    ldapconnector,
    ldapsyntax,
)
from ldaptor import usage, config
from twisted.internet import reactor


def move(client, fromDN, toDN):
    e = ldapsyntax.LDAPEntry(client=client, dn=fromDN)
    d = e.move(toDN)
    return d


exitStatus = 0


def error(fail):
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


def main(cfg, fromDN, toDN, binddn, bindPassword):
    fromDN = distinguishedname.DistinguishedName(stringValue=fromDN)
    toDN = distinguishedname.DistinguishedName(stringValue=toDN)

    c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d = c.connect(dn=fromDN, overrides=cfg.getServiceLocationOverrides())

    def _bind(proto, binddn, bindPassword):
        if binddn:
            pwd = bindPassword
            if pwd is None:
                pwd = getpass.getpass("Password for %s: " % binddn)
            d = proto.bind(binddn, pwd)
        else:
            d = proto.bind()
        d.addCallback(lambda _: proto)
        return d

    d.addCallback(_bind, binddn, bindPassword)

    d.addCallback(move, fromDN, toDN)
    d.addErrback(error)
    d.addBoth(lambda x: reactor.stop())

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(usage.Options, usage.Options_service_location, usage.Options_bind):
    """LDAPtor object rename utility"""

    def parseArgs(self, fromDN, toDN):
        self.opts["from"] = fromDN
        self.opts["to"] = toDN


def console_script():
    try:
        opts = MyOptions()
        opts.parseOptions()
    except usage.UsageError as ue:
        sys.stderr.write("{}: {}\n".format(sys.argv[0], ue))
        sys.exit(1)

    from twisted.python import log

    log.startLogging(sys.stderr, setStdout=0)

    cfg = config.LDAPConfig(serviceLocationOverrides=opts["service-location"])

    bindPassword = None
    if opts["bind-auth-fd"]:
        f = os.fdopen(opts["bind-auth-fd"])
        bindPassword = f.readline()
        assert bindPassword[-1] == "\n"
        bindPassword = bindPassword[:-1]
        f.close()

    main(cfg, opts["from"], opts["to"], opts["binddn"], bindPassword)


if __name__ == "__main__":
    sys.exit(console_script())
