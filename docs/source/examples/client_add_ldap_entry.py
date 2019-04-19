#! /usr/bin/env python

import sys

from twisted.internet import defer
from twisted.internet.endpoints import clientFromString, connectProtocol
from twisted.internet.task import react
from twisted.python import log
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols import pureber, pureldap


def entry_to_attributes(entry):
    """
    Convert a simple mapping to the data structures required for an
    entry in the DIT.

    Returns: (dn, attributes)
    """
    attributes = {}
    dn = None
    for prop, value in entry.items():
        if prop == 'dn':
            dn = value
            continue
        attributes.setdefault(prop, set()).add(value)
    if dn is None:
        raise Exception("Entry needs to include key, `dn`!")
    ldap_attributes = []
    for attrib, values in attributes.items():
        ldap_attribute_type = pureldap.LDAPAttributeDescription(attrib)
        ldap_attribute_values = []
        for value in values:
            ldap_attribute_values.append(pureldap.LDAPAttributeValue(value))
        ldap_values = pureber.BERSet(ldap_attribute_values)
        ldap_attributes.append((ldap_attribute_type, ldap_values))
    return dn, ldap_attributes


@defer.inlineCallbacks
def onConnect(client, entry):
    dn, attributes = entry_to_attributes(entry)
    op = pureldap.LDAPAddRequest(entry=dn, attributes=attributes)
    response = yield client.send(op)
    if response.resultCode != 0:
        log.err("DIT reported error code {}: {}".format(
            response.resultCode, response.errorMessage))


def onError(err, reactor):
    if reactor.running:
        log.err(err)
        reactor.stop()


def main(reactor):
    log.startLogging(sys.stdout)
    entry = {
        "dn": "gn=Jane+sn=Doe,ou=people,dc=example,dc=fr",
        "c": "US",
        "gn": "Jane",
        "l": "Philadelphia",
        "objectClass": "addressbookPerson",
        "postalAddress": "230",
        "postalCode": "314159",
        "sn": "Doe",
        "st": "PA",
        "street": "Mobius Strip",
        "userPassword": "terces",
    }
    endpoint_str = "tcp:host=localhost:port=8080"
    e = clientFromString(reactor, endpoint_str)
    d = connectProtocol(e, LDAPClient())
    d.addCallback(onConnect, entry)
    d.addErrback(onError, reactor)
    return d


react(main)
