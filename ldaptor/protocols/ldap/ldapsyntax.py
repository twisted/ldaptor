"""Pythonic API for LDAP operations."""

from twisted.internet import defer
from twisted.python.failure import Failure
from ldaptor.protocols.ldap import ldapclient, ldif, distinguishedname, ldaperrors
from ldaptor.protocols import pureldap
from ldaptor.samba import smbpassword
from ldaptor import ldapfilter

class PasswordSetAggregateError(Exception):
    """Some of the password plugins failed."""
    def __init__(self, errors):
        Exception.__init__(self)
        self.errors=errors

    def __str__(self):
        return str(self.errors)

    def __repr__(self):
        return '<'+self.__class__.__name__+' errors='+repr(self.errors)+'>'

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
        self.key=key
        self.val=val

    def __str__(self):
        if self.val is None:
            r=repr(self.key)
        else:
            r='%s=%s' % (repr(self.key), repr(self.val))
        return """The attribute to be removed, %s, is the RDN for the object and cannot be removed.""" % r

class LDAPJournalOperation:
    pass

class LDAPJournalOperation_Replace(LDAPJournalOperation):
    def __init__(self, key, value):
	self.key=key
	self.value=value

    def asLDAPModification(self):
	return pureldap.LDAPModification_replace(
	    vals=((self.key, self.value),)
	    )

class LDAPJournalOperation_Delete(LDAPJournalOperation):
    def __init__(self, key):
	self.key=key

    def asLDAPModification(self):
	return pureldap.LDAPModification_delete(
	    vals=((self.key,),)
	    )

class LDAPJournalOperation_Attribute_Append(LDAPJournalOperation):
    def __init__(self, key, value):
	self.key=key
	self.value=value

    def asLDAPModification(self):
	return pureldap.LDAPModification_add(
	    vals=((self.key, self.value),)
	    )

class LDAPJournalOperation_Attribute_Delete(LDAPJournalOperation):
    def __init__(self, key, value):
	self.key=key
	self.value=value

    def asLDAPModification(self):
	return pureldap.LDAPModification_delete(
	    vals=((self.key, self.value),)
	    )

class LDAPAttributeSet:
    # TODO make this a subclass of Set when 2.3 is out
    def __init__(self, ldapObject, key, values=None):
	self.ldapObject = ldapObject
	self.key = key
	self.data = {}
	if values is not None:
	    for value in values:
		self.data[value]=1

    def add(self, value):
	self.ldapObject.journal(
	    LDAPJournalOperation_Attribute_Append(self.key, (value,)))
	self.data[value]=1

    def update(self, sequence):
	self.ldapObject.journal(
	    LDAPJournalOperation_Attribute_Append(self.key, sequence))
	for x in (sequence or ()):
	    self.data[x]=1

    def remove(self, value):
	if not self.data.has_key(value):
	    raise LookupError, value
        self.ldapObject._canRemove(self.key, value)
	self.ldapObject.journal(
	    LDAPJournalOperation_Attribute_Delete(self.key, (value,)))
	del self.data[value]

    def discard(self, value):
	try:
	    self.remove(value)
	except LookupError:
	    pass

    def pop(self):
	for value in self.data.keys():
	    self.remove(value)
	    return value
	raise LookupError

    def clear(self):
        self.ldapObject._canRemoveAll(self.key)
	self.data.clear()
	self.ldapObject.journal(
	    LDAPJournalOperation_Delete(self.key))

    def __repr__(self):
	values=self.data.keys()
	values.sort()
	attributes=', '.join([repr(x) for x in values])
	return '[%s]' % (
	    attributes)

    def __len__(self):
	return len(self.data)

    def __iter__(self):
	return self.data.iterkeys()

    def iterkeys(self):
	return self.data.iterkeys()

    def __contains__(self, value):
	return value in self.data

    def __eq__(self, other):
	"""
	>>> o1=LDAPAttributeSet(None, None, ['b', 'c', 'a'])
	>>> o2=LDAPAttributeSet(None, None, ['c', 'b', 'a'])
	>>> o1==o2
	1
	>>> o3=LDAPAttributeSet(None, None, ['b', 'c', 'X'])
	>>> o1==o3
	0
	>>> o2==o3
	0
	>>> o1==['c', 'b', 'a']
	1
	"""
	if isinstance(other, LDAPAttributeSet):
	    return self.data == other.data
	else:
	    me=self.data.keys()
	    me.sort()
	    him=list(other)
	    him.sort()
	    return me == him

    def __ne__(self, other):
	return not self==other

class LDAPEntry:
    """

    Pythonic API for LDAP object access and modification.

    >>> o=LDAPEntry(client=ldapclient.LDAPClient(),
    ...     dn='cn=foo,dc=example,dc=com',
    ...     attributes={'anAttribute': ['itsValue', 'secondValue'],
    ...     'onemore': ['aValue'],
    ...     })
    >>> o
    LDAPEntry(dn='cn=foo,dc=example,dc=com', attributes={'anAttribute': ['itsValue', 'secondValue'], 'onemore': ['aValue']})

    """

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

	self.client=client
        if not isinstance(dn, distinguishedname.DistinguishedName):
            dn=distinguishedname.DistinguishedName(stringValue=dn)
	self.dn=dn

	self._attributes={}
	for k,vs in attributes.items():
	    self._attributes[k] = LDAPAttributeSet(self, k, vs)
        self.complete = complete

	self._journal=[]

	self._attributeCache={}
	self._attributeCache.update(self._attributes)

        self._state = 'ready'

    def _canRemove(self, key, value):
        """

        Called by LDAPAttributeSet when it is about to remove a value
        of an attributeType.

        """
        self._checkState()
        for rdn in self.dn.split()[0].split():
            if rdn.attributeType == key and rdn.value == value:
                raise CannotRemoveRDNError, (key, value)

    def _canRemoveAll(self, key):
        """

        Called by LDAPAttributeSet when it is about to remove all values
        of an attributeType.

        """
        self._checkState()
        import types
        assert not isinstance(self.dn, types.StringType)
        for keyval in self.dn.split()[0].split():
            if keyval.attributeType == key:
                raise CannotRemoveRDNError, (key)



    def _checkState(self):
        if self._state != 'ready':
            if self._state == 'deleted':
                raise ObjectDeletedError
            else:
                raise ObjectInBadStateError, \
                      "State is %s while expecting %s" \
                      % (repr(self._state), repr('ready'))

    def __getitem__(self, key):
	"""

	Get all values of an attribute.

	>>> o=LDAPEntry(client=ldapclient.LDAPClient(),
	...     dn='cn=foo,dc=example,dc=com',
	...     attributes={'anAttribute': ['itsValue']})
	>>> o['anAttribute']
	['itsValue']

	"""
        self._checkState()
	return self._attributeCache[key]

    def get(self, key, default=None):
	"""

	Get all values of an attribute.

	>>> o=LDAPEntry(client=ldapclient.LDAPClient(),
	...     dn='cn=foo,dc=example,dc=com',
	...     attributes={'anAttribute': ['itsValue']})
	>>> o.get('anAttribute')
	['itsValue']
	>>> o.get('foo')
	>>> o.get('foo', [])
	[]

	"""
        self._checkState()
	return self._attributeCache.get(key, default)

    def journal(self, journalOperation):
        """

        Add an LDAPJournalOperation into the list of modifications
        that need to be flushed to the LDAP server.

        Normal callers should not use this, they should use the
        o['foo']=['bar', 'baz'] -style API that enforces schema,
        handles errors and updates the cached data.

        """
        self._journal.append(journalOperation)

    def __setitem__(self, key, value):
	"""

	Set values of an attribute. Please use lists. Do not modify
	the lists in place, that's not supported _yet_.

	>>> o=LDAPEntry(client=ldapclient.LDAPClient(),
	...     dn='cn=foo,dc=example,dc=com',
	...     attributes={'anAttribute': ['itsValue']})
	>>> o['anAttribute']=['foo', 'bar']
	>>> o['anAttribute']
	['bar', 'foo']

	"""
        self._checkState()
        self._canRemoveAll(key)

	new=LDAPAttributeSet(self, key, value)
	self._attributeCache[key]=new
	self.journal(LDAPJournalOperation_Replace(key, value))

    def __delitem__(self, key):
	"""

	Delete all values of an attribute.

	>>> o=LDAPEntry(client=ldapclient.LDAPClient(),
	...     dn='cn=foo,dc=example,dc=com',
	...     attributes={
	...     'anAttribute': ['itsValue', 'secondValue'],
	...     'another': ['moreValues'],
	...     })
	>>> del o['anAttribute']
	>>> o
	LDAPEntry(dn='cn=foo,dc=example,dc=com', attributes={'another': ['moreValues']})

	"""
        self._checkState()
        self._canRemoveAll(key)

	del self._attributeCache[key]
	self.journal(LDAPJournalOperation_Delete(key))

    def has_key(self, key):
        self._checkState()
	return key in self._attributeCache

    def __contains__(self, key):
        return self.has_key(key)

    def undo(self):
	"""

	Forget all pending changes.

	"""
        self._checkState()
	new={}
	new.update(self._attributes)
	self._attributeCache=new
	self._journal=[]

    def _commit_success(self, data):
	new={}
	new.update(self._attributeCache)
	self._attributes=new
	self._journal=[]
        return data

    def _cbCommit(self, msg, d):
	assert isinstance(msg, pureldap.LDAPModifyResponse)
	assert msg.referral is None #TODO
	if msg.resultCode==ldaperrors.Success.resultCode:
	    assert msg.matchedDN==''
	    d.callback(self)
	else:
	    d.errback(ldaperrors.get(msg.resultCode, msg.errorMessage))
	return 1

    def commit(self):
	"""

	Send all pending changes to the LDAP server.

	@returns: a Deferred that tells you whether the
	operation succeeded or not. (TODO specify how)

	"""
        self._checkState()
        if not self._journal:
            return defer.succeed(self)
	d=defer.Deferred()

        try:
            op=pureldap.LDAPModifyRequest(
                object=str(self.dn),
                modification=[x.asLDAPModification() for x in self._journal])
            self.client.queue(
                op, (lambda
                     msg,
                     d=d,
                     self=self:
                     self._cbCommit(msg, d)))
	except ldapclient.LDAPClientConnectionLostException:
	    d.errback(Failure())
        else:
            d.addCallback(self._commit_success)
	return d

    def keys(self):
        self._checkState()
	return self._attributeCache.keys()

    def __len__(self):
	return len(self.keys())

    def items(self):
        self._checkState()
	return self._attributeCache.items()

    def __repr__(self):
	x={}
	for key in self.keys():
	    x[key]=self[key]
	keys=self.keys()
	keys.sort()
	a=[]
	for key in keys:
	    a.append('%s: %s' % (repr(key), repr(self[key])))
	attributes=', '.join(a)
	return '%s(dn=%s, attributes={%s})' % (
	    self.__class__.__name__,
	    repr(str(self.dn)),
	    attributes)

    def _cbSearchEntry(self, callback, objectName, attributes, complete):
	attrib={}
	for key, values in attributes:
	    attrib[str(key)]=[str(x) for x in values]
	o=LDAPEntry(client=self.client,
                    dn=objectName,
                    attributes=attrib,
                    complete=complete)
	callback(o)

    def _cbSearchMsg(self, msg, d, callback, complete, sizeLimitIsNonFatal):
	if isinstance(msg, pureldap.LDAPSearchResultDone):
	    assert msg.referral is None #TODO
            e = ldaperrors.get(msg.resultCode, msg.errorMessage)
            if not isinstance(e, ldaperrors.Success):
		try:
                    raise e
                except ldaperrors.LDAPSizeLimitExceeded, e:
                    if sizeLimitIsNonFatal:
                        pass
		except:
		    d.errback(Failure())
                    return 1

            # search ended successfully
            assert msg.matchedDN==''
            d.callback(None)
	    return 1
	else:
	    assert isinstance(msg, pureldap.LDAPSearchResultEntry)
	    self._cbSearchEntry(callback, msg.objectName, msg.attributes,
                                complete=complete)
	    return 0

    def search(self,
	       filterText=None,
	       filterObject=None,
	       attributes=(),
	       scope=pureldap.LDAP_SCOPE_wholeSubtree,
	       derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
	       sizeLimit=0,
	       sizeLimitIsNonFatal=False,
	       timeLimit=0,
	       typesOnly=0,
	       callback=None):
	"""

	Perform an LDAP search with this object as the base.

	@param filterText: LDAP search filter as a string.

	@param filterObject: LDAP search filter as LDAPFilter.
	Note if both filterText and filterObject are given, they
	are combined with AND. If neither is given, the search is
	made with a filter that matches everything.

	@param attributes: List of attributes to retrieve for the
	result objects. An empty list and means all.

	@param scope: Whether to recurse into subtrees.

	@param derefAliases: Whether to deref LDAP aliases. TODO write
	better documentation.

	@param sizeLimit: At most how many entries to return. 0 means
	unlimited.

	@param timeLimit: At most how long to use for processing the
	search request. 0 means unlimited.

	@param typesOnly: Whether to return attribute types only, or
	also values.

	@param callback: Callback function to call for each resulting
	LDAPEntry. None means gather the results into a list and give
	that to the Deferred returned from here.

	@return: A Deferred that will complete when the search is
	done. The Deferred gives None if callback was given and a list
	of the search results if callback is not given or is None.

	"""
        self._checkState()
	d=defer.Deferred()
	if filterObject is None and filterText is None:
	    filterObject=pureldap.LDAPFilterMatchAll
	elif filterObject is None and filterText is not None:
	    filterObject=ldapfilter.parseFilter(filterText)
	elif filterObject is not None and filterText is None:
	    pass
	elif filterObject is not None and filterText is not None:
	    f=ldapfilter.parseFilter(filterText)
	    filterObject=pureldap.LDAPFilter_and((f, filterObject))

	results=[]
	if callback is None:
	    cb=results.append
	else:
	    cb=callback
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
	    self.client.queue(
		op, (lambda
		     msg,
		     d=d,
		     callback=cb,
		     self=self:
		     self._cbSearchMsg(msg, d, callback, complete=not attributes,
                                       sizeLimitIsNonFatal=sizeLimitIsNonFatal)))
	except ldapclient.LDAPClientConnectionLostException:
	    d.errback(Failure())
	else:
	    if callback is None:
		d.addCallback(lambda dummy: results)
	return d

    def __str__(self):
	"""

	Stringify as LDIF.

	>>> o=LDAPEntry(client=ldapclient.LDAPClient(),
	...     dn='cn=foo,dc=example,dc=com',
	...     attributes={'anAttribute': ['itsValue', 'secondValue'],
	...     'onemore': ['aValue'],
	...	})
	>>> # must use rstrip or doctests won't like it due to the empty line
	>>> # you can just say "print o"
	>>> print str(o).rstrip()
	dn: cn=foo,dc=example,dc=com
	anAttribute: itsValue
	anAttribute: secondValue
	onemore: aValue

	"""
	a=[]

	objectClasses = list(self._attributeCache.get('objectClass', []))
	objectClasses.sort()
	a.append(('objectClass', objectClasses))

	l=list(self._attributeCache.items())
	l.sort()
	for key, values in l:
	    if key!='objectClass':
		a.append((key, values))
	return ldif.asLDIF(self.dn, a)

    def __eq__(self, other):
	"""

	Comparison. Only equality is supported.

	>>> client=ldapclient.LDAPClient()
	>>> a=LDAPEntry(client=client,
	...             dn='dc=example,dc=com')
	>>> b=LDAPEntry(client=client,
	...             dn='dc=example,dc=com')
	>>> a==b
	1
	>>> c=LDAPEntry(client=ldapclient.LDAPClient(),
	...             dn='ou=different,dc=example,dc=com')
	>>> a==c
	0

	Comparison does not consider the client of the object.

	>>> anotherClient=ldapclient.LDAPClient()
	>>> d=LDAPEntry(client=anotherClient,
	...             dn='dc=example,dc=com')
	>>> a==d
	1

	"""
	if not isinstance(other, self.__class__):
	    return 0
	if self.dn != other.dn:
	    return 0

	my=self.keys()
	my.sort()
	its=other.keys()
	its.sort()
	if my!=its:
	    return 0
	for key in my:
	    myAttr=self[key]
	    itsAttr=other[key]
	    if myAttr!=itsAttr:
		return 0
	return 1

    def __ne__(self, other):
	"""

	Inequality comparison. See L{__eq__}.

	"""
	return not self==other

    def __nonzero__(self):
        return True

    def _cbMoveDone(self, msg, d):
	assert isinstance(msg, pureldap.LDAPModifyDNResponse)
	assert msg.referral is None #TODO
	if msg.resultCode==ldaperrors.Success.resultCode:
	    assert msg.matchedDN==''
	    d.callback(self)
	else:
	    d.errback(ldaperrors.get(msg.resultCode, msg.errorMessage))
	return 1

    def move(self, newDN):
        """

        Move the object to a new DN.

        @param newDN: the new DistinguishedName
        
	@return: A Deferred that will complete when the move is done.

        """
        self._checkState()
	assert isinstance(newDN, distinguishedname.DistinguishedName), \
	       "LDAPEntry.move() needs an attribute of type DistinguishedName."
	d = defer.Deferred()

	newrdn=newDN.split()[0]
	newSuperior=distinguishedname.DistinguishedName(listOfRDNs=newDN.split()[1:])
	op = pureldap.LDAPModifyDNRequest(entry=str(self.dn),
					  newrdn=str(newrdn),
					  deleteoldrdn=0,
					  newSuperior=str(newSuperior))
	self.client.queue(op, lambda msg, self=self, d=d: self._cbMoveDone(msg, d))
	return d

    def _cbDeleteDone(self, msg, d):
	assert isinstance(msg, pureldap.LDAPDelResponse)
	assert msg.referral is None #TODO
	if msg.resultCode==ldaperrors.Success.resultCode:
	    assert msg.matchedDN==''
	    d.callback(self)
	else:
            d.errback(ldaperrors.get(msg.resultCode, msg.errorMessage))
        return 1

    def delete(self):
        """

        Delete this object from the LDAP server.

	@return: A Deferred that will complete when the delete is done.

        """
        self._checkState()
	d = defer.Deferred()

	op = pureldap.LDAPDelRequest(entry=str(self.dn))
	self.client.queue(op, lambda msg, self=self, d=d: self._cbDeleteDone(msg, d))
        self._state = 'deleted'
	return d

    def _cbNamingContext_Entries(self, results):
        for result in results:
            for namingContext in result.get('namingContexts', ()):
                dn = distinguishedname.DistinguishedName(namingContext)
                if dn.contains(self.dn):
                    return LDAPEntry(self.client, dn)
        raise NoContainingNamingContext, self.dn

    def namingContext(self):
        """

        Return an LDAPEntry for the naming context that contains this object.

        """

        o=LDAPEntry(client=self.client, dn='')
        d=o.search(filterText='(objectClass=*)',
                   scope=pureldap.LDAP_SCOPE_baseObject,
                   attributes=['namingContexts'])
	d.addCallback(self._cbNamingContext_Entries)
        return d

    def _cbSetPassword_ExtendedOperation(self, msg, d):
	assert isinstance(msg, pureldap.LDAPExtendedResponse)
	assert msg.referral is None #TODO
	if msg.resultCode==ldaperrors.Success.resultCode:
	    assert msg.matchedDN==''
	    d.callback(self)
	else:
            d.errback(ldaperrors.get(msg.resultCode, msg.errorMessage))
        return 1

    def setPassword_ExtendedOperation(self, newPasswd):
        """

        Set the password on this object.

        @param newPasswd: A string containing the new password.

	@return: A Deferred that will complete when the operation is
	done.
        
        """

        self._checkState()
	d = defer.Deferred()

	op = pureldap.LDAPPasswordModifyRequest(userIdentity=str(self.dn), newPasswd=newPasswd)
	self.client.queue(op, lambda msg, self=self, d=d: self._cbSetPassword_ExtendedOperation(msg, d))
	return d

    _setPasswordPriority_ExtendedOperation=0
    setPasswordMaybe_ExtendedOperation = setPassword_ExtendedOperation

    def setPassword_Samba(self, newPasswd):
        """

        Set the Samba password on this object.

        @param newPasswd: A string containing the new password.

	@return: A Deferred that will complete when the operation is
	done.
        
        """

        self._checkState()

	nthash=smbpassword.nthash(newPasswd)
	lmhash=smbpassword.lmhash(newPasswd)

        self['ntPassword'] = [nthash]
        self['lmPassword'] = [lmhash]
	return self.commit()

    _setPasswordPriority_Samba=20
    def setPasswordMaybe_Samba(self, newPasswd):
        """

        Set the Samba password on this object if it is a sambaAccount.

        @param newPasswd: A string containing the new password.

	@return: A Deferred that will complete when the operation is
	done.

        """
        if not self.complete and not self.has_key('objectClass'):
            d=self.fetch('objectClass')
            d.addCallback(lambda dummy, self=self, newPasswd=newPasswd:
                          self.setPasswordMaybe_Samba(newPasswd))
        else:
            if 'sambaAccount' in self.get('objectClass', ()):
                d = self.setPassword_Samba(newPasswd)
            else:
                d = defer.succeed(self)
        return d

    def _cbSetPassword(self, dl, names):
        assert len(dl)==len(names)
        l=[]
        for name, (ok, x) in zip(names, dl):
            if not ok:
                l.append((name, x))
        if l:
            raise PasswordSetAggregateError, l
        return self

    def setPassword(self, newPasswd):
        """

        Set all applicable passwords for this object.

        @param newPasswd: A string containing the new password.

	@return: A Deferred that will complete when the operation is
	done.

        """
        def _passwordChangerPriorityComparison(me, other):
            mePri = getattr(self, '_setPasswordPriority_'+me)
            otherPri = getattr(self, '_setPasswordPriority_'+other)
            return cmp(mePri, otherPri)

        prefix='setPasswordMaybe_'
        names=[name[len(prefix):] for name in dir(self) if name.startswith(prefix)]
        names.sort(_passwordChangerPriorityComparison)

        l=[]
        for name in names:        
            fn=getattr(self, prefix+name)
            d=fn(newPasswd)
            l.append(d)
        dl = defer.DeferredList(l)
        for d in l:
            # Eat the failure or it will be logged.
            # DeferredList already got its copy, so we
            # don't lose any information here.
            d.addErrback(lambda dummy: None)
        dl.addCallback(self._cbSetPassword, names)
        return dl

    def _cbFetch(self, results, overWrite):
        if len(results)!=1:
            raise DNNotPresentError, self.dn
        o=results[0]

        assert not self._journal

        if not overWrite:
            self._attributes.clear()
            overWrite=o.keys()
            self.complete = 1

        for k in overWrite:
            vs=o.get(k)
            if vs is not None:
                self._attributes[k] = LDAPAttributeSet(self, k, vs)
        self.undo()
        return self

    def fetch(self, *attributes):
        """

        Fetch the attributes of this object from the server.

        @params: Attributes to fetch. If none, fetch all
        attributes. Fetched attributes are overwritten, and if
        fetching all attributes, attributes that are not on the server
        are removed.

        @return: A Deferred that will complete when the operation is
        done.

        """

        self._checkState()
        if self._journal:
            raise ObjectDirtyError, 'cannot fetch attributes of %s, it is dirty' % repr(self)

        d = self.search(scope=pureldap.LDAP_SCOPE_baseObject,
                        attributes=attributes)
        d.addCallback(self._cbFetch, overWrite=attributes)
        return d

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
