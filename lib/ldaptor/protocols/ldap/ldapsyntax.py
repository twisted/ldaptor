"""Pythonic API for LDAP operations."""

from twisted.internet import defer
from twisted.python.failure import Failure
from ldaptor.protocols.ldap import ldapclient, ldapfilter, ldif, distinguishedname, ldaperrors
from ldaptor.protocols import pureldap

class DNNotPresentError(Exception):
    """The requested DN cannot be found by the server."""
    pass

class LDAPJournal_Replace:
    def __init__(self, key, value):
        self.key=key
        self.value=value

    def asLDAPModification(self):
        return pureldap.LDAPModification_replace(
            vals=((self.key, self.value),)
            )

class LDAPJournal_Delete:
    def __init__(self, key):
        self.key=key

    def asLDAPModification(self):
        return pureldap.LDAPModification_delete(
            vals=((self.key,),)
            )

class LDAPJournal_Attribute_Append:
    def __init__(self, key, value):
        self.key=key
        self.value=value

    def asLDAPModification(self):
        return pureldap.LDAPModification_add(
            vals=((self.key, self.value),)
            )

class LDAPJournal_Attribute_Delete:
    def __init__(self, key, value):
        self.key=key
        self.value=value

    def asLDAPModification(self):
        return pureldap.LDAPModification_delete(
            vals=((self.key, self.value),)
            )

class LDAPSearchProcessResult(ldapclient.LDAPSearch):
    def __init__(self, callback, *a, **kw):
        self.callback=callback
        ldapclient.LDAPSearch.__init__(self, *a, **kw)

    def handle_entry(self, objectName, attributes):
        self.callback(objectName, attributes)

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
        self.ldapObject._journal.append(
            LDAPJournal_Attribute_Append(self.key, (value,)))
        self.data[value]=1

    def update(self, sequence):
        self.ldapObject._journal.append(
            LDAPJournal_Attribute_Append(self.key, sequence))
        for x in (sequence or ()):
            self.data[x]=1

    def remove(self, value):
        if not self.data.has_key(value):
            raise LookupError, value
        self.ldapObject._journal.append(
            LDAPJournal_Attribute_Delete(self.key, (value,)))
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
        self.data.clear()
        self.ldapObject._journal.append(
            LDAPJournal_Delete(self.key))

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

    def __contain__(self, value):
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
            import sys
            return me == him

    def __ne__(self, other):
        return not self==other

class LDAPObject:
    """

    Pythonic API for LDAP object access and modification.

    >>> o=LDAPObject(client=ldapclient.LDAPClient(),
    ...     dn='cn=foo,dc=example,dc=com',
    ...     attributes={'anAttribute': ['itsValue', 'secondValue'],
    ...     'onemore': ['aValue'],
    ...     })
    >>> o
    LDAPObject(dn='cn=foo,dc=example,dc=com', attributes={'anAttribute': ['itsValue', 'secondValue'], 'onemore': ['aValue']})
    

    """
    def __init__(self, client, dn, attributes={}):
        """

        Initialize the object.

        @param client: The LDAP client connection this object belongs
        to.

        @param dn: Distinguished Name of the object, as a string.

        @param attributes: Attributes of the object. A dictionary of
        attribute types to list of attribute values.

        """

        self.client=client
        self.dn=dn

        self._attributes={}
        for k,vs in attributes.items():
            self._attributes[k] = LDAPAttributeSet(self, k, vs)

        self._journal=[]

        self._attributeCache={}
        self._attributeCache.update(self._attributes)

    def __getitem__(self, key):
        """

        Get all values of an attribute.

        >>> o=LDAPObject(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o['anAttribute']
        ['itsValue']

        """
        return self._attributeCache[key]

    def get(self, key, default=None):
        """

        Get all values of an attribute.

        >>> o=LDAPObject(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o.get('anAttribute')
        ['itsValue']
        >>> o.get('foo')
        >>> o.get('foo', [])
        []

        """
        return self._attributeCache.get(key, default)

    def __setitem__(self, key, value):
        """

        Set values of an attribute. Please use lists. Do not modify
        the lists in place, that's not supported _yet_.

        >>> o=LDAPObject(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={'anAttribute': ['itsValue']})
        >>> o['anAttribute']=['foo', 'bar']
        >>> o['anAttribute']
        ['bar', 'foo']

        """
        new=LDAPAttributeSet(self, key, value)
        self._attributeCache[key]=new
        self._journal.append(LDAPJournal_Replace(key, value))

    def __delitem__(self, key):
        """

        Delete all values of an attribute.

        >>> o=LDAPObject(client=ldapclient.LDAPClient(),
        ...     dn='cn=foo,dc=example,dc=com',
        ...     attributes={
        ...     'anAttribute': ['itsValue', 'secondValue'],
        ...     'another': ['moreValues'],
        ...     })
        >>> del o['anAttribute']
        >>> o
        LDAPObject(dn='cn=foo,dc=example,dc=com', attributes={'another': ['moreValues']})

        """
        del self._attributeCache[key]
        self._journal.append(LDAPJournal_Delete(key))

    def has_key(self, key):
        return key in self._attributeCache

    def undo(self):
        """

        Forget all pending changes.

        """
        new={}
        new.update(self._attributes)
        self._attributeCache=new
        self._journal=[]

    def _commit_success(self, dummy):
        new={}
        new.update(self._attributeCache)
        self._attributes=new
        self._journal=[]

    def commit(self):
        """

        Send all pending changes to the LDAP server.

        @returns: a Deferred that tells you whether the
        operation succeeded or not. (TODO specify how)

        """
        d=defer.Deferred()

        d.addCallback(self._commit_success)

        ldapclient.LDAPModifyAttributes(
            d,
            self.client,
            self.dn,
            [x.asLDAPModification() for x in self._journal])
        
        return d

    def keys(self):
        return self._attributeCache.keys()

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
            repr(self.dn),
            attributes)

    def _cbSearchEntry(self, callback, objectName, attributes):
        attrib={}
        for key, values in attributes:
            attrib[str(key)]=[str(x) for x in values]
        o=LDAPObject(client=self.client,
                     dn=objectName,
                     attributes=attrib)
        callback(o)

    def _cbSearchMsg(self, msg, d, callback):
        if isinstance(msg, pureldap.LDAPSearchResultDone):
            assert msg.referral==None #TODO
            if msg.resultCode==0: #TODO ldap.errors.success
                assert msg.matchedDN==''
                d.callback(None)
            else:
                try:
                    raise ldaperrors.get(msg.resultCode, msg.errorMessage)
                except:
                    self.deferred.errback(Failure())
            return 1
        else:
            assert isinstance(msg, pureldap.LDAPSearchResultEntry)
            self._cbSearchEntry(callback, msg.objectName, msg.attributes)
            return 0

    def search(self,
               filterText=None,
               filterObject=None,
               attributes=(),
               scope=pureldap.LDAP_SCOPE_wholeSubtree,
               derefAliases=pureldap.LDAP_DEREF_neverDerefAliases,
               sizeLimit=0,
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
        LDAPObject. None means gather the results into a list and give
        that to the Deferred returned from here.

        @return: A Deferred that will complete when the search is
        done. The Deferred gives None if callback was given and a list
        of the search results if callback is not given or is None.

        """        
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
                baseObject=self.dn,
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
                     callback=cb:
                     self._cbSearchMsg(msg, d, callback)))
        except ldapclient.LDAPClientConnectionLostException:
            d.errback(Failure())
        else:
            if callback is None:
                d.addCallback(lambda dummy: results)
        return d

    def __str__(self):
        """

        Stringify as LDIF.

        >>> o=LDAPObject(client=ldapclient.LDAPClient(),
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
        >>> a=LDAPObject(client=client,
        ...              dn='dc=example,dc=com')
        >>> b=LDAPObject(client=client,
        ...              dn='dc=example,dc=com')
        >>> a==b
        1
        >>> c=LDAPObject(client=ldapclient.LDAPClient(),
        ...              dn='ou=different,dc=example,dc=com')
        >>> a==c
        0

        Comparison does not consider the client of the object.

        >>> anotherClient=ldapclient.LDAPClient()
        >>> d=LDAPObject(client=anotherClient,
        ...              dn='dc=example,dc=com')
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

    def _cbMoveDone(self, msg, d):
        assert isinstance(msg, pureldap.LDAPModifyDNResponse)
        assert msg.referral==None #TODO
        if msg.resultCode==ldaperrors.errors['success']:
            assert msg.matchedDN==''
            d.callback(self)
        else:
            d.errback(ldaperrors.get(msg.resultCode, msg.errorMessage))
        return 1

    def move(self, newDN):
        assert isinstance(newDN, distinguishedname.DistinguishedName), \
               "LDAPObject.move() needs an attribute of type DistinguishedName."
        d = defer.Deferred()

        newrdn=newDN.split()[0]
        newSuperior=distinguishedname.DistinguishedName(listOfRDNs=newDN.split()[1:])
        op = pureldap.LDAPModifyDNRequest(entry=str(self.dn),
                                          newrdn=str(newrdn),
                                          deleteoldrdn=0,
                                          newSuperior=str(newSuperior))
        self.client.queue(op, lambda msg, d=d: self._cbMoveDone(msg, d))
        return d
