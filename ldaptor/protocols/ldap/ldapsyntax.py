"""Pythonic API for LDAP operations."""
import functools

import six
from twisted.internet import defer
from twisted.python.failure import Failure
from zope.interface import implementer

from ldaptor.protocols.ldap import ldapclient, ldif, distinguishedname, ldaperrors
from ldaptor.protocols import pureldap, pureber
from ldaptor.samba import smbpassword
from ldaptor import ldapfilter, interfaces, delta, attributeset, entry


class PasswordSetAggregateError(Exception):
    """Some of the password plugins failed"""

    def __init__(self, errors):
        Exception.__init__(self)
        self.errors = errors

    def __str__(self):
        return '%s: %s.' % (
            self.__doc__,
            '; '.join(['%s failed with %s' % (name, fail.getErrorMessage())
                       for name, fail in self.errors]))

    def __repr__(self):
        return '<' + self.__class__.__name__ + ' errors=' + repr(self.errors) + '>'


class PasswordSetAborted(Exception):
    """Aborted"""

    def __str__(self):
        return self.__doc__


class DNNotPresentError(Exception):
    """The requested DN cannot be found by the server."""
    pass


class ObjectInBadStateError(Exception):
    """The LDAP object in in a bad state."""
    pass


class ObjectDeletedError(ObjectInBadStateError):
    """The LDAP object has already been removed, unable to perform operations on it."""
    pass


class ObjectDirtyError(ObjectInBadStateError):
    """The LDAP object has a journal which needs to be committed or undone before this operation."""
    pass


class NoContainingNamingContext(Exception):
    """The server contains to LDAP naming context that would contain this object."""
    pass


class CannotRemoveRDNError(Exception):
    """The attribute to be removed is the RDN for the object and cannot be removed."""

    def __init__(self, key, val=None):
        Exception.__init__(self)
        self.key = key
        self.val = val

    def __str__(self):
        if self.val is None:
            r = repr(self.key)
        else:
            r = '%s=%s' % (repr(self.key), repr(self.val))
        return """The attribute to be removed, %s, is the RDN for the object and cannot be removed.""" % r


class MatchNotImplemented(NotImplementedError):
    """Match type not implemented"""

    def __init__(self, op):
        Exception.__init__(self)
        self.op = op

    def __str__(self):
        return '%s: %r' % (self.__doc__, self.op)


class JournaledLDAPAttributeSet(attributeset.LDAPAttributeSet):
    def __init__(self, ldapObject, *a, **kw):
        self.ldapObject = ldapObject
        super(JournaledLDAPAttributeSet, self).__init__(*a, **kw)

    def add(self, value):
        self.ldapObject.journal(delta.Add(self.key, [value]))
        super(JournaledLDAPAttributeSet, self).add(value)

    def update(self, sequence):
        self.ldapObject.journal(delta.Add(self.key, sequence))
        super(JournaledLDAPAttributeSet, self).update(sequence)

    def remove(self, value):
        if value not in self:
            raise LookupError(value)
        self.ldapObject._canRemove(self.key, value)
        self.ldapObject.journal(delta.Delete(self.key, [value]))
        super(JournaledLDAPAttributeSet, self).remove(value)

    def clear(self):
        self.ldapObject._canRemoveAll(self.key)
        super(JournaledLDAPAttributeSet, self).clear()
        self.ldapObject.journal(delta.Delete(self.key))


@implementer(
    interfaces.ILDAPEntry,
    interfaces.IEditableLDAPEntry,
    interfaces.IConnectedLDAPEntry,
)
class LDAPEntryWithClient(entry.EditableLDAPEntry):
    _state = 'invalid'
    """

    State of an LDAPEntry is one of:

    invalid - object not initialized yet

    ready - normal

    deleted - object has been deleted

    """

    def __init__(self, client, dn, attributes={}, complete=0):
        """

        Initialize the object.

        @param client: The LDAP client connection this object belongs
        to.

        @param dn: Distinguished Name of the object, as a string.

        @param attributes: Attributes of the object. A dictionary of
        attribute types to list of attribute values.

        """

        super(LDAPEntryWithClient, self).__init__(dn, attributes)
        self.client = client
        self.complete = complete

        self._journal = []

        self._remoteData = entry.EditableLDAPEntry(dn, attributes)
        self._state = 'ready'

    def buildAttributeSet(self, key, values):
        return JournaledLDAPAttributeSet(self, key, values)

    def _canRemove(self, key, value):
        """

        Called by JournaledLDAPAttributeSet when it is about to remove a value
        of an attributeType.

        """
        self._checkState()
        for rdn in self.dn.split()[0].split():
            if rdn.attributeType == key and rdn.value == value:
                raise CannotRemoveRDNError(key, value)

    def _canRemoveAll(self, key):
        """

        Called by JournaledLDAPAttributeSet when it is about to remove all values
        of an attributeType.

        """
        self._checkState()
        assert not isinstance(self.dn, six.string_types)
        for keyval in self.dn.split()[0].split():
            if keyval.attributeType == key:
                raise CannotRemoveRDNError(key)

    def _checkState(self):
        if self._state != 'ready':
            if self._state == 'deleted':
                raise ObjectDeletedError
            else:
                raise ObjectInBadStateError(
                    "State is %s while expecting %s" % (
                        repr(self._state), repr('ready')))

    def journal(self, journalOperation):
        """

        Add a Modification into the list of modifications
        that need to be flushed to the LDAP server.

        Normal callers should not use this, they should use the
        o['foo']=['bar', 'baz'] -style API that enforces schema,
        handles errors and updates the cached data.

        """
        self._journal.append(journalOperation)

    # start ILDAPEntry
    def __getitem__(self, *a, **kw):
        self._checkState()
        return super(LDAPEntryWithClient, self).__getitem__(*a, **kw)

    def get(self, *a, **kw):
        self._checkState()
        return super(LDAPEntryWithClient, self).get(*a, **kw)

    def has_key(self, *a, **kw):
        self._checkState()
        return super(LDAPEntryWithClient, self).has_key(*a, **kw)

    def __contains__(self, key):
        self._checkState()
        return self.has_key(key)

    def keys(self):
        self._checkState()
        return super(LDAPEntryWithClient, self).keys()

    def items(self):
        self._checkState()
        return super(LDAPEntryWithClient, self).items()

    def __str__(self):
        a = []

        objectClasses = list(self.get('objectClass', []))
        objectClasses.sort()
        a.append(('objectClass', objectClasses))

        l = list(self.items())
        l.sort()
        for key, values in l:
            if key != 'objectClass':
                a.append((key, values))
        return ldif.asLDIF(self.dn, a)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return 0
        if self.dn != other.dn:
            return 0

        my=self.keys()
        my.sort()
        its=other.keys()
        its.sort()
        if my != its:
            return 0
        for key in my:
            myAttr = self[key]
            itsAttr = other[key]
            if myAttr != itsAttr:
                return 0
        return 1

    def __ne__(self, other):
        return not self == other

    def __len__(self):
        return len(self.keys())

    def __nonzero__(self):
        return True

    def __hash__(self):
        return id(self)


    def bind(self, password):
        r = pureldap.LDAPBindRequest(dn=str(self.dn), auth=password)
        d = self.client.send(r)
        d.addCallback(self._handle_bind_msg)
        return d

    def _handle_bind_msg(self, msg):
        assert isinstance(msg, pureldap.LDAPBindResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(msg.resultCode, msg.errorMessage)
        return self

    # end ILDAPEntry

    # start IEditableLDAPEntry
    def __setitem__(self, key, value):
        self._checkState()
        self._canRemoveAll(key)

        new = JournaledLDAPAttributeSet(self, key, value)
        super(LDAPEntryWithClient, self).__setitem__(key, new)
        self.journal(delta.Replace(key, value))

    def __delitem__(self, key):
        self._checkState()
        self._canRemoveAll(key)

        super(LDAPEntryWithClient, self).__delitem__(key)
        self.journal(delta.Delete(key))

    def undo(self):
        self._checkState()
        self._attributes.clear()
        for k, vs in self._remoteData.items():
            self._attributes[k] = self.buildAttributeSet(k, vs)
        self._journal = []

    def _commit_success(self, msg):
        assert isinstance(msg, pureldap.LDAPModifyResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(msg.resultCode, msg.errorMessage)

        assert msg.matchedDN == ''

        self._remoteData = entry.EditableLDAPEntry(self.dn, self)
        self._journal = []
        return self

    def commit(self):
        self._checkState()
        if not self._journal:
            return defer.succeed(self)

        op = pureldap.LDAPModifyRequest(
            object=str(self.dn),
            modification=[x.asLDAP() for x in self._journal])
        d = defer.maybeDeferred(self.client.send, op)
        d.addCallback(self._commit_success)
        return d

    def _cbMoveDone(self, msg, newDN):
        assert isinstance(msg, pureldap.LDAPModifyDNResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(msg.resultCode, msg.errorMessage)

        assert msg.matchedDN == ''
        self.dn = newDN
        return self

    def move(self, newDN):
        self._checkState()
        newDN = distinguishedname.DistinguishedName(newDN)

        newrdn = newDN.split()[0]
        newSuperior = distinguishedname.DistinguishedName(listOfRDNs=newDN.split()[1:])
        newDN = distinguishedname.DistinguishedName((newrdn,) + newSuperior.split())
        op = pureldap.LDAPModifyDNRequest(entry=str(self.dn),
                                          newrdn=str(newrdn),
                                          deleteoldrdn=1,
                                          newSuperior=str(newSuperior))
        d = self.client.send(op)
        d.addCallback(self._cbMoveDone, newDN)
        return d

    def _cbDeleteDone(self, msg):
        assert isinstance(msg, pureldap.LDAPResult)
        if not isinstance(msg, pureldap.LDAPDelResponse):
            raise ldaperrors.get(msg.resultCode,
                                 msg.errorMessage)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(msg.resultCode, msg.errorMessage)

        assert msg.matchedDN == ''
        return self

    def delete(self):
        self._checkState()

        op = pureldap.LDAPDelRequest(entry=str(self.dn))
        d = self.client.send(op)
        d.addCallback(self._cbDeleteDone)
        self._state = 'deleted'
        return d

    def _cbAddDone(self, msg, dn):
        assert isinstance(msg, pureldap.LDAPAddResponse), \
            "LDAPRequest response was not an LDAPAddResponse: %r" % msg
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(msg.resultCode, msg.errorMessage)

        assert msg.matchedDN == ''
        e = self.__class__(dn=dn, client=self.client)
        return e

    def addChild(self, rdn, attributes):
        self._checkState()

        a = []
        if attributes.get('objectClass', None):
            a.append(('objectClass', attributes['objectClass']))
            del attributes['objectClass']
        attributes = a + sorted(attributes.items())
        del a
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        dn = distinguishedname.DistinguishedName(
            listOfRDNs=(rdn,) + self.dn.split())

        ldapAttrs = []
        for attrType, values in attributes:
            ldapAttrType = pureldap.LDAPAttributeDescription(attrType)
            l = []
            for value in values:
                if (isinstance(value, six.text_type)):
                    value = value.encode('utf-8')
                l.append(pureldap.LDAPAttributeValue(value))
            ldapValues = pureber.BERSet(l)
            ldapAttrs.append((ldapAttrType, ldapValues))
        op=pureldap.LDAPAddRequest(entry=str(dn),
                                   attributes=ldapAttrs)
        d = self.client.send(op)
        d.addCallback(self._cbAddDone, dn)
        return d

    def _cbSetPassword_ExtendedOperation(self, msg):
        assert isinstance(msg, pureldap.LDAPExtendedResponse)
        assert msg.referral is None  # TODO
        if msg.resultCode != ldaperrors.Success.resultCode:
            raise ldaperrors.get(msg.resultCode, msg.errorMessage)

        assert msg.matchedDN == ''
        return self

    def setPassword_ExtendedOperation(self, newPasswd):
        """

        Set the password on this object.

        @param newPasswd: A string containing the new password.

        @return: A Deferred that will complete when the operation is
        done.

        """

        self._checkState()

        op = pureldap.LDAPPasswordModifyRequest(userIdentity=str(self.dn), newPasswd=newPasswd)
        d = self.client.send(op)
        d.addCallback(self._cbSetPassword_ExtendedOperation)
        return d

    _setPasswordPriority_ExtendedOperation = 0
    setPasswordMaybe_ExtendedOperation = setPassword_ExtendedOperation

    def setPassword_Samba(self, newPasswd, style=None):
        """

        Set the Samba password on this object.

        @param newPasswd: A string containing the new password.

        @param style: one of 'sambaSamAccount', 'sambaAccount' or
        None. Specifies the style of samba accounts used. None is
        default and is the same as 'sambaSamAccount'.

        @return: A Deferred that will complete when the operation is
        done.

        """

        self._checkState()

        nthash = smbpassword.nthash(newPasswd)
        lmhash = smbpassword.lmhash(newPasswd)

        if style is None:
            style = 'sambaSamAccount'
        if style == 'sambaSamAccount':
            self['sambaNTPassword'] = [nthash]
            self['sambaLMPassword'] = [lmhash]
        elif style == 'sambaAccount':
            self['ntPassword'] = [nthash]
            self['lmPassword'] = [lmhash]
        else:
            raise RuntimeError("Unknown samba password style %r" % style)
        return self.commit()

    _setPasswordPriority_Samba = 20

    def setPasswordMaybe_Samba(self, newPasswd):
        """

        Set the Samba password on this object if it is a
        sambaSamAccount or sambaAccount.

        @param newPasswd: A string containing the new password.

        @return: A Deferred that will complete when the operation is
        done.

        """
        if not self.complete and not self.has_key('objectClass'):
            d = self.fetch('objectClass')
            d.addCallback(lambda dummy, self=self, newPasswd=newPasswd:
                          self.setPasswordMaybe_Samba(newPasswd))
        else:
            objectClasses = [s.upper() for s in self.get('objectClass', ())]
            if 'sambaAccount'.upper() in objectClasses:
                d = self.setPassword_Samba(newPasswd, style="sambaAccount")
            elif 'sambaSamAccount'.upper() in objectClasses:
                d = self.setPassword_Samba(newPasswd, style="sambaSamAccount")
            else:
                d = defer.succeed(self)
        return d

    def _cbSetPassword(self, dl, names):
        assert len(dl) == len(names)
        l = []
        for name, (ok, x) in zip(names, dl):
            if not ok:
                l.append((name, x))
        if l:
            raise PasswordSetAggregateError(l)
        return self

    def _cbSetPassword_one(self, result):
        return (True, None)

    def _ebSetPassword_one(self, fail):
        fail.trap(ldaperrors.LDAPException,
                  DNNotPresentError)
        return (False, fail)

    def _setPasswordAll(self, results, newPasswd, prefix, names):
        if not names:
            return results
        name, names = names[0], names[1:]
        if results and not results[-1][0]:
            # failing
            fail = Failure(PasswordSetAborted())
            d = defer.succeed(results + [(None, fail)])
        else:
            fn = getattr(self, prefix + name)
            d = defer.maybeDeferred(fn, newPasswd)
            d.addCallbacks(self._cbSetPassword_one,
                           self._ebSetPassword_one)

            def cb(result):
                (success, info) = result
                return results + [(success, info)]

            d.addCallback(cb)

        d.addCallback(self._setPasswordAll,
                      newPasswd, prefix, names)
        return d

    def setPassword(self, newPasswd):
        def _passwordChangerPriorityComparison(me, other):
            mePri = getattr(self, '_setPasswordPriority_' + me)
            otherPri = getattr(self, '_setPasswordPriority_' + other)
            return (mePri > otherPri) - (mePri < otherPri)

        prefix = 'setPasswordMaybe_'
        names = [name[len(prefix):] for name in dir(self) if name.startswith(prefix)]
        names.sort(
            key=functools.cmp_to_key(_passwordChangerPriorityComparison))

        d = defer.maybeDeferred(self._setPasswordAll,
                                [],
                                newPasswd,
                                prefix,
                                names)
        d.addCallback(self._cbSetPassword, names)
        return d

    # end IEditableLDAPEntry

    # start IConnectedLDAPEntry

    def _cbNamingContext_Entries(self, results):
        for result in results:
            for namingContext in result.get('namingContexts', ()):
                dn = distinguishedname.DistinguishedName(namingContext)
                if dn.contains(self.dn):
                    return LDAPEntry(self.client, dn)
        raise NoContainingNamingContext(self.dn)

    def namingContext(self):
        o = LDAPEntry(client=self.client, dn='')
        d = o.search(filterText='(objectClass=*)',
                     scope=pureldap.LDAP_SCOPE_baseObject,
                     attributes=['namingContexts'])
        d.addCallback(self._cbNamingContext_Entries)
        return d

    def _cbFetch(self, results, overWrite):
        if len(results) != 1:
            raise DNNotPresentError(self.dn)
        o = results[0]

        assert not self._journal

        if not overWrite:
            for key in list(self._remoteData.keys()):
                del self._remoteData[key]
            overWrite = o.keys()
            self.complete = 1

        for k in overWrite:
            vs = o.get(k)
            if vs is not None:
                self._remoteData[k] = vs
        self.undo()
        return self

    def fetch(self, *attributes):
        self._checkState()
        if self._journal:
            raise ObjectDirtyError("cannot fetch attributes of %s, it is dirty" % repr(self))

        d = self.search(scope=pureldap.LDAP_SCOPE_baseObject,
                        attributes=attributes)
        d.addCallback(self._cbFetch, overWrite=attributes)
        return d

    def _cbSearchEntry(self, callback, objectName, attributes, complete):
        attrib = {}
        for key, values in attributes:
            attrib[str(key)] = [str(x) for x in values]
        o = LDAPEntry(client=self.client,
                      dn=objectName,
                      attributes=attrib,
                      complete=complete)
        callback(o)

    def _cbSearchMsg(self, msg, d, callback, complete, sizeLimitIsNonFatal):
        if isinstance(msg, pureldap.LDAPSearchResultDone):
            assert msg.referral is None  # TODO
            e = ldaperrors.get(msg.resultCode, msg.errorMessage)
            if not isinstance(e, ldaperrors.Success):
                try:
                    raise e
                except ldaperrors.LDAPSizeLimitExceeded:
                    if sizeLimitIsNonFatal:
                        pass
                except:
                    d.errback(Failure())
                    return True

            # search ended successfully
            assert msg.matchedDN == ''
            d.callback(None)
            return True
        elif isinstance(msg, pureldap.LDAPSearchResultEntry):
            self._cbSearchEntry(callback, msg.objectName, msg.attributes,
                                complete=complete)
            return False
        elif isinstance(msg, pureldap.LDAPSearchResultReference):
            return False
        else:
            raise ldaperrors.LDAPProtocolError("bad search response: %r" % msg)

    def search(self,
               filterText=None,
               filterObject=None,
               attributes=(),
               scope=None,
               derefAliases=None,
               sizeLimit=0,
               sizeLimitIsNonFatal=False,
               timeLimit=0,
               typesOnly=0,
               callback=None):
        self._checkState()
        d = defer.Deferred()
        if filterObject is None and filterText is None:
            filterObject = pureldap.LDAPFilterMatchAll
        elif filterObject is None and filterText is not None:
            filterObject = ldapfilter.parseFilter(filterText)
        elif filterObject is not None and filterText is None:
            pass
        elif filterObject is not None and filterText is not None:
            f = ldapfilter.parseFilter(filterText)
            filterObject = pureldap.LDAPFilter_and((f, filterObject))

        if scope is None:
            scope = pureldap.LDAP_SCOPE_wholeSubtree
        if derefAliases is None:
            derefAliases = pureldap.LDAP_DEREF_neverDerefAliases

        if attributes is None:
            attributes = ['1.1']

        results = []
        if callback is None:
            cb = results.append
        else:
            cb = callback
        try:
            op = pureldap.LDAPSearchRequest(
                baseObject=str(self.dn),
                scope=scope,
                derefAliases=derefAliases,
                sizeLimit=sizeLimit,
                timeLimit=timeLimit,
                typesOnly=typesOnly,
                filter=filterObject,
                attributes=attributes)
            dsend = self.client.send_multiResponse(
                op, self._cbSearchMsg,
                d, cb, complete=not attributes,
                sizeLimitIsNonFatal=sizeLimitIsNonFatal)
        except ldapclient.LDAPClientConnectionLostException:
            d.errback(Failure())
        else:
            if callback is None:
                d.addCallback(lambda dummy: results)

            def rerouteerr(e):
                d.errback(e)
                # returning None will stop the error
                # from being propagated and logged.

            dsend.addErrback(rerouteerr)
        return d

    def lookup(self, dn):
        e = self.__class__(self.client, dn)
        d = e.fetch('1.1')
        return d

    # end IConnectedLDAPEntry

    def __repr__(self):
        x = {}
        for key in super(LDAPEntryWithClient, self).keys():
            x[key] = self[key]
        keys = list(x.keys())
        keys.sort()
        a = []
        for key in keys:
            a.append('%s: %s' % (repr(key), repr(self[key])))
        attributes = ', '.join(a)
        return '%s(dn=%s, attributes={%s})' % (
            self.__class__.__name__,
            repr(str(self.dn)),
            attributes)


# API backwards compatibility
LDAPEntry = LDAPEntryWithClient


class LDAPEntryWithAutoFill(LDAPEntry):
    def __init__(self, *args, **kwargs):
        LDAPEntry.__init__(self, *args, **kwargs)
        self.autoFillers = []

    def _cb_addAutofiller(self, r, autoFiller):
        self.autoFillers.append(autoFiller)
        return r

    def addAutofiller(self, autoFiller):
        d = defer.maybeDeferred(autoFiller.start, self)
        d.addCallback(self._cb_addAutofiller, autoFiller)
        return d

    def journal(self, journalOperation):
        LDAPEntry.journal(self, journalOperation)
        for autoFiller in self.autoFillers:
            autoFiller.notify(self, journalOperation.key)
