import sys
from ldaptor.protocols.ldap import ldapclient, ldapconnector, fetchschema
from ldaptor import usage, config
from twisted.internet import reactor


def _printResults(x):
    attributeTypes, objectClasses = x

    something = False
    for at in attributeTypes:
        print("attributetype", at)
        something = True

    if something:
        print()

    for oc in objectClasses:
        print("objectclass", oc)


exitStatus = 0


def error(fail):
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
        d = fetchschema.fetch(client, baseDN)
        return d

    d.addCallback(_cbBound, baseDN)
    d.addCallback(_printResults)
    d.addErrback(error)
    d.addBoth(lambda x: reactor.stop())

    reactor.run()
    sys.exit(exitStatus)


class MyOptions(
    usage.Options, usage.Options_service_location, usage.Options_base_optional
):
    """LDAPtor command line schema fetching utility"""


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
