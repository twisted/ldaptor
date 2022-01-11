import sys
from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector
from ldaptor import usage, numberalloc, config
from twisted.internet import reactor

exitStatus = 0


def error(fail):
    print(fail)
    print("fail:", fail.getErrorMessage(), file=sys.stderr)
    global exitStatus
    exitStatus = 1


def main(cfg):
    try:
        baseDN = cfg.getBaseDN()
    except config.MissingBaseDNError as e:
        print(f"{sys.argv[0]}: {e}.", file=sys.stderr)
        sys.exit(1)

    c = ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
    d = c.connectAnonymously(dn=baseDN, overrides=cfg.getServiceLocationOverrides())

    def _cbBound(client, baseDN):
        o = ldapsyntax.LDAPEntry(client=client, dn=baseDN)
        return numberalloc.getFreeNumber(o, "uidNumber", min=1000)

    d.addCallback(_cbBound, baseDN)
    d.addCallback(lambda num: sys.stdout.write("%s\n" % repr(num)))
    d.addErrback(error)
    d.addBoth(lambda x: reactor.stop())

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """LDAPtor command line search utility"""


def console_script():
    from twisted.python import log

    log.startLogging(sys.stderr, setStdout=0)

    try:
        opts = MyOptions()
        opts.parseOptions()
    except usage.UsageError as ue:
        sys.stderr.write(f"{sys.argv[0]}: {ue}\n")
        sys.exit(1)

    cfg = config.LDAPConfig(
        baseDN=opts["base"], serviceLocationOverrides=opts["service-location"]
    )
    main(cfg)


if __name__ == "__main__":
    sys.exit(console_script())
