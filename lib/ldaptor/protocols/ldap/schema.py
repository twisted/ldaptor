from ldaptor.protocols.ldap import ldapclient, ldaperrors
from ldaptor.protocols import pureldap

class LDAPGet_subschemaSubentry(ldapclient.LDAPSearch):
    def __init__(self, deferred, client, dn):
        ldapclient.LDAPSearch.__init__(self, deferred, client,
                                       baseObject=dn,
                                       scope=pureldap.LDAP_SCOPE_baseObject,
                                       sizeLimit=1,
                                       attributes=["subschemaSubentry"],
                                       )
        self.found=0
        self.dn=None
        self.subschemaSubentry=None
        deferred.addCallbacks(self._ok, lambda x: x)
            
    def _ok(self, dummy):
        if self.found==0:
            raise ldaperrors.LDAPUnknownError(ldaperrors.other, "No such DN")
        elif self.found==1:
            return self.subschemaSubentry
        else:
            raise ldaperrors.LDAPUnknownError(ldaperrors.other,
                                              "DN matched multiple entries")

    def handle_entry(self, objectName, attributes):
        self.found=self.found+1
        self.dn=objectName
        for k,v in attributes:
            if k=="subschemaSubentry":
                assert len(v)==1, "More than one subschemaSubentry is not support yet. TODO"
                self.subschemaSubentry=v[0]
        assert self.subschemaSubentry, "LDAP server doesn't support subschemaSubentry, dn=%s"%self.dn

class LDAPGetSchema(ldapclient.LDAPSearch):
    def __init__(self, deferred, client, dn):
        ldapclient.LDAPSearch.__init__(self, deferred, client,
                                       baseObject=dn,
                                       scope=pureldap.LDAP_SCOPE_baseObject,
                                       sizeLimit=1,
                                       attributes=["attributeTypes",
                                                   "objectClasses"],
                                       )
        self.found=0
        self.dn=None
        self.attributeTypes=[]
        self.objectClasses=[]
        deferred.addCallbacks(self._ok, lambda x: x)
            
    def _ok(self, dummy):
        if self.found==0:
            raise ldaperrors.LDAPUnknownError(ldaperrors.other, "No such DN")
        elif self.found==1:
            return (self.attributeTypes, self.objectClasses)
        else:
            raise ldaperrors.LDAPUnknownError(ldaperrors.other,
                                              "DN matched multiple entries")


    def handle_entry(self, objectName, attributes):
        self.found=self.found+1
        self.dn=objectName
        for k,v in attributes:
            if k=="attributeTypes":
                for text in v:
                    self.attributeTypes.append(AttributeTypeDescription(str(text)))
            elif k=="objectClasses":
                for text in v:
                    self.objectClasses.append(ObjectClassDescription(str(text)))
        assert self.attributeTypes, "LDAP server doesn't give attributeTypes for subschemaSubentry dn=%s"%self.dn

class ASN1ParserThingie:
    def _to_list(self, text):
        """Split text into $-separated list."""
        r=[]
        for x in text.split("$"):
            while x.startswith(" "):
                x=x[1:]
            while x.endswith(" "):
                x=x[:-1]
            assert x
            r.append(x)
        return tuple(r)

    def _strings_to_list(self, text):
        """Split ''-quoted strings into list."""
        r=[]
        while text:
            while text.startswith(" "):
                text=text[1:]
            if not text:
                break
            assert text[0]=="'", "Text %s must start with a single quote."%repr(text)
            text=text[1:]
            end=text.index("'")
            r.append(text[:end])
            text=text[end+1:]
        return tuple(r)

class ObjectClassDescription(ASN1ParserThingie):
    """
    d               = "0" / "1" / "2" / "3" / "4" /
                      "5" / "6" / "7" / "8" / "9"

    numericstring   = 1*d

    numericoid      = numericstring *( "." numericstring )

    space           = 1*" "

    whsp            = [ space ]

    descr           = keystring

    qdescr          = whsp "'" descr "'" whsp

    qdescrlist      = [ qdescr *( qdescr ) ]

    ; object descriptors used as schema element names
    qdescrs         = qdescr / ( whsp "(" qdescrlist ")" whsp )

    dstring         = 1*utf8

    qdstring        = whsp "'" dstring "'" whsp

    descr           = keystring

    oid             = descr / numericoid

    woid            = whsp oid whsp

    ; set of oids of either form
    oids            = woid / ( "(" oidlist ")" )

    ObjectClassDescription = "(" whsp
    	numericoid whsp      ; ObjectClass identifier
        [ "NAME" qdescrs ]
        [ "DESC" qdstring ]
        [ "OBSOLETE" whsp ]
        [ "SUP" oids ]       ; Superior ObjectClasses
        [ ( "ABSTRACT" / "STRUCTURAL" / "AUXILIARY" ) whsp ]
        			; default structural
	[ "MUST" oids ]      ; AttributeTypes
        [ "MAY" oids ]       ; AttributeTypes
        whsp ")"
    """


    def __init__(self, text):
        self.oid=None
        self.name=None
        self.desc=None
        self.obsolete=0
        self.sup=[]
        self.type=None
        self.must=[]
        self.may=[]

        assert text[0]=='(', "Text %s must be in parentheses."%repr(text)
        assert text[-1]==')', "Text %s must be in parentheses."%repr(text)
        text=text[1:-1]
        while text.startswith(" "):
            text=text[1:]

        # oid
        end=text.index(" ")
        self.oid=text[:end]
        text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("NAME "):
            text=text[len("NAME "):]
            while text.startswith(" "):
                text=text[1:]
            if text[0]=="'":
                text=text[1:]
                end=text.index("'")
                self.name=(text[:end],)
                text=text[end+1:]
            elif text[0]=="(":
                text=text[1:]
                while text.startswith(" "):
                    text=text[1:]
                end=text.index(")")
                self.name=self._strings_to_list(text[:end])
                text=text[end+1:]
            else:
                raise "TODO"


        while text.startswith(" "):
            text=text[1:]

        if text.startswith("DESC "):
            text=text[len("DESC "):]
            while text.startswith(" "):
                text=text[1:]
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("OBSOLETE "):
            self.obsolete=1
            text=text[len("OBSOLETE "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("SUP "):
            text=text[len("SUP "):]
            while text.startswith(" "):
                text=text[1:]
            if text[0]=="(":
                text=text[1:]
                while text.startswith(" "):
                    text=text[1:]
                end=text.index(")")
                self.sup=self._to_list(text[:end])
                text=text[end+1:]
            else:
                end=text.index(" ")
                self.sup=[text[:end]]
                text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("ABSTRACT "):
            assert self.type==None
            self.type="ABSTRACT"
            text=text[len("ABSTRACT "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("STRUCTURAL "):
            assert self.type==None
            self.type="STRUCTURAL"
            text=text[len("STRUCTURAL "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("AUXILIARY "):
            assert self.type==None
            self.type="AUXILIARY"
            text=text[len("AUXILIARY "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("MUST "):
            text=text[len("MUST "):]
            while text.startswith(" "):
                text=text[1:]
            if text[0]=="(":
                text=text[1:]
                while text.startswith(" "):
                    text=text[1:]
                end=text.index(")")
                self.must=self._to_list(text[:end])
                text=text[end+1:]
            else:
                end=text.index(" ")
                self.must.append(text[:end])
                text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("MAY "):
            text=text[len("MAY "):]
            while text.startswith(" "):
                text=text[1:]
            if text[0]=="(":
                text=text[1:]
                while text.startswith(" "):
                    text=text[1:]
                end=text.index(")")
                self.may=self._to_list(text[:end])
                text=text[end+1:]
            else:
                end=text.index(" ")
                self.may.append(text[:end])
                text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        assert text=="", "Text was not empty: %s"%repr(text)

        if not self.type:
            self.type="STRUCTURAL"

        assert self.oid
        for c in self.oid:
            assert c in "0123456789."
        assert self.name==None or self.name
        assert self.type in ("ABSTRACT", "STRUCTURAL", "AUXILIARY")

    def __repr__(self):
        nice = {}
        for k,v in self.__dict__.items():
            nice[k]=repr(v)
        return ("<%s instance at 0x%x"%(self.__class__.__name__, id(self))
                +(" oid=%(oid)s name=%(name)s desc=%(desc)s"
                  +" obsolete=%(obsolete)s sup=%(sup)s type=%(type)s"
                  +" must=%(must)s may=%(may)s>")%nice)
                

class AttributeTypeDescription(ASN1ParserThingie):
    """
    AttributeTypeDescription = "(" whsp
    	numericoid whsp              ; AttributeType identifier
        [ "NAME" qdescrs ]             ; name used in AttributeType
        [ "DESC" qdstring ]            ; description
        [ "OBSOLETE" whsp ]
        [ "SUP" woid ]                 ; derived from this other AttributeType
        [ "EQUALITY" woid              ; Matching Rule name
        [ "ORDERING" woid              ; Matching Rule name
        [ "SUBSTR" woid ]              ; Matching Rule name
        [ "SYNTAX" whsp noidlen whsp ] ; see section 4.3
        [ "SINGLE-VALUE" whsp ]        ; default multi-valued
        [ "COLLECTIVE" whsp ]          ; default not collective
        [ "NO-USER-MODIFICATION" whsp ]; default user modifiable
        [ "USAGE" whsp AttributeUsage ]; default userApplications
        whsp ")"

    AttributeUsage =
    	"userApplications"     /
        "directoryOperation"   /
        "distributedOperation" / ; DSA-shared
        "dSAOperation"          ; DSA-specific, value depends on server

    noidlen = numericoid [ "{" len "}" ]

    len     = numericstring
    """

    def __init__(self, text):
        self.oid=None
        self.name=None
        self.desc=None
        self.obsolete=0
        self.sup=[]
        self.equality=None
        self.ordering=None
        self.substr=None
        self.syntax=None
        self.single_value=None
        self.collective=None
        self.no_user_modification=None
        self.usage=None

        assert text[0]=='(', "Text %s must be in parentheses."%repr(text)
        assert text[-1]==')', "Text %s must be in parentheses."%repr(text)
        text=text[1:-1]
        while text.startswith(" "):
            text=text[1:]

        # oid
        end=text.index(" ")
        self.oid=text[:end]
        text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("NAME "):
            text=text[len("NAME "):]
            while text.startswith(" "):
                text=text[1:]
            if text[0]=="'":
                text=text[1:]
                end=text.index("'")
                self.name=(text[:end],)
                text=text[end+1:]
            elif text[0]=="(":
                text=text[1:]
                while text.startswith(" "):
                    text=text[1:]
                end=text.index(")")
                self.name=self._strings_to_list(text[:end])
                text=text[end+1:]
            else:
                raise "TODO"


        while text.startswith(" "):
            text=text[1:]

        if text.startswith("DESC "):
            text=text[len("DESC "):]
            while text.startswith(" "):
                text=text[1:]
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("OBSOLETE "):
            self.obsolete=1
            text=text[len("OBSOLETE "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("SUP "):
            text=text[len("SUP "):]
            while text.startswith(" "):
                text=text[1:]
            end=text.index(" ")
            self.sup=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("EQUALITY "):
            text=text[len("EQUALITY "):]
            while text.startswith(" "):
                text=text[1:]
            end=text.index(" ")
            self.equality=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("ORDERING "):
            text=text[len("ORDERING "):]
            while text.startswith(" "):
                text=text[1:]
            end=text.index(" ")
            self.ordering=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("SUBSTR "):
            text=text[len("SUBSTR "):]
            while text.startswith(" "):
                text=text[1:]
            end=text.index(" ")
            self.substr=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("SYNTAX "):
            text=text[len("SYNTAX "):]
            while text.startswith(" "):
                text=text[1:]
            end=text.index(" ")
            self.syntax=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("SINGLE-VALUE "):
            assert self.single_value==None
            self.single_value=1
            text=text[len("SINGLE-VALUE "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("COLLECTIVE "):
            assert self.collective==None
            self.collective=1
            text=text[len("COLLECTIVE "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("NO-USER-MODIFICATION "):
            assert self.no_user_modification==None
            self.no_user_modification=1
            text=text[len("NO-USER-MODIFICATION "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("USAGE "):
            assert self.usage==None
            text=text[len("USAGE "):]
            while text.startswith(" "):
                text=text[1:]
            end=text.index(" ")
            self.usage=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        assert text=="", "Text was not empty: %s"%repr(text)

        if self.single_value==None:
            self.single_value=0

        if self.collective==None:
            self.collective=0

        if self.no_user_modification==None:
            self.no_user_modification=0

        assert self.oid
        for c in self.oid:
            assert c in "0123456789."
        assert self.name==None or self.name
        assert self.usage==None or self.usage in (
            "userApplications",
            "directoryOperation",
            "distributedOperation",
            "dSAOperation",
            )

    def __repr__(self):
        nice = {}
        for k,v in self.__dict__.items():
            nice[k]=repr(v)
        return ("<%s instance at 0x%x"%(self.__class__.__name__, id(self))
                +(" oid=%(oid)s name=%(name)s desc=%(desc)s"
                  +" obsolete=%(obsolete)s sup=%(sup)s"
                  +" equality=%(equality)s ordering=%(ordering)s"
                  +" substr=%(substr)s syntax=%(syntax)s"
                  +" single_value=%(single_value)s"
                  +" collective=%(collective)s"
                  +" no_user_modification=%(no_user_modification)s"
                  +" usage=%(usage)s>")%nice)


class SyntaxDescription(ASN1ParserThingie):
    """
    SyntaxDescription = "(" whsp
    	numericoid whsp
        [ "DESC" qdstring ]
        whsp ")"
    """

    def __init__(self, text):
        self.oid=None
        self.desc=None

        assert text[0]=='('
        assert text[-1]==')'
        text=text[1:-1]
        while text.startswith(" "):
            text=text[1:]

        # oid
        end=text.index(" ")
        self.oid=text[:end]
        text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("DESC "):
            text=text[len("DESC "):]
            while text.startswith(" "):
                text=text[1:]
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("X-BINARY-TRANSFER-REQUIRED "):
            text=text[len("X-BINARY-TRANSFER-REQUIRED "):]
            while text.startswith(" "):
                text=text[1:]
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("X-NOT-HUMAN-READABLE "):
            text=text[len("X-NOT-HUMAN-READABLE "):]
            while text.startswith(" "):
                text=text[1:]
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        assert text=="", "Text was not empty: %s"%repr(text)

        assert self.oid
        for c in self.oid:
            assert c in "0123456789."

    def __repr__(self):
        nice = {}
        for k,v in self.__dict__.items():
            nice[k]=repr(v)
        return ("<%s instance at 0x%x"%(self.__class__.__name__, id(self))
                +(" oid=%(oid)s desc=%(desc)s>")%nice)



class MatchingRuleDescription(ASN1ParserThingie):
    """
    MatchingRuleDescription = "(" whsp
    	numericoid whsp  ; MatchingRule identifier
        [ "NAME" qdescrs ]
        [ "DESC" qdstring ]
        [ "OBSOLETE" whsp ]
        "SYNTAX" numericoid
        whsp ")"
    """

    def __init__(self, text):
        self.oid=None
        self.name=None
        self.desc=None
        self.obsolete=None
        self.syntax=None

        assert text[0]=='('
        assert text[-1]==')'
        text=text[1:-1]
        while text.startswith(" "):
            text=text[1:]

        # oid
        end=text.index(" ")
        self.oid=text[:end]
        text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("NAME "):
            text=text[len("NAME "):]
            while text.startswith(" "):
                text=text[1:]
            if text[0]=="'":
                text=text[1:]
                end=text.index("'")
                self.name=(text[:end],)
                text=text[end+1:]
            elif text[0]=="(":
                text=text[1:]
                while text.startswith(" "):
                    text=text[1:]
                end=text.index(")")
                self.name=self._strings_to_list(text[:end])
                text=text[end+1:]
            else:
                raise "TODO"

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("DESC "):
            text=text[len("DESC "):]
            while text.startswith(" "):
                text=text[1:]
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("OBSOLETE "):
            self.obsolete=1
            text=text[len("OBSOLETE "):]

        while text.startswith(" "):
            text=text[1:]

        if text.startswith("SYNTAX "):
            text=text[len("SYNTAX "):]
            while text.startswith(" "):
                text=text[1:]
            end=text.index(" ")
            self.syntax=text[:end]
            text=text[end+1:]

        while text.startswith(" "):
            text=text[1:]

        assert text=="", "Text was not empty: %s"%repr(text)

        if self.obsolete==None:
            self.obsolete=0
        assert self.oid
        for c in self.oid:
            assert c in "0123456789."
        assert self.syntax

    def __repr__(self):
        nice = {}
        for k,v in self.__dict__.items():
            nice[k]=repr(v)
        return ("<%s instance at 0x%x"%(self.__class__.__name__, id(self))
                +(" oid=%(oid)s desc=%(desc)s>")%nice)
