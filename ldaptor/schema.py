def extractWord(text):
    if not text:
        return None
    l = text.split(None, 1)
    word = l[0]
    try:
        text = l[1]
    except IndexError:
        text = ''
    return word, text

def peekWord(text):
    if not text:
        return None
    return text.split(None, 1)[0]

class ASN1ParserThingie:
    def _to_list(self, text):
        """Split text into $-separated list."""
        r=[]
        for x in text.split("$"):
            x = x.strip()
            assert x
            r.append(x)
        return tuple(r)

    def _strings_to_list(self, text):
        """Split ''-quoted strings into list."""
        r=[]
        while text:
            text = text.lstrip()
            if not text:
                break
            assert text[0]=="'", "Text %s must start with a single quote."%repr(text)
            text=text[1:]
            end=text.index("'")
            r.append(text[:end])
            text=text[end+1:]
        return tuple(r)

    def _str_list(self, l):
        s = ' '.join([self._str(x) for x in l])
        if len(l) > 1:
            s = '( %s )' % s
        return s

    def _list(self, l):
        s = ' $ '.join([x for x in l])
        if len(l) > 1:
            s = '( %s )' % s
        return s

    def _str(self, s):
        return "'%s'" % s

class ObjectClassDescription(ASN1ParserThingie):
    """
    ASN Syntax::

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

        if text is not None:
            self._parse(text)

    def _parse(self, text):
        assert text[0]=='(', "Text %s must be in parentheses."%repr(text)
        assert text[-1]==')', "Text %s must be in parentheses."%repr(text)
        text=text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "NAME":
            text=text[len("NAME "):]
            text = text.lstrip()
            if text[0]=="'":
                text=text[1:]
                end=text.index("'")
                self.name=(text[:end],)
                text=text[end+1:]
            elif text[0]=="(":
                text=text[1:]
                text = text.lstrip()
                end=text.index(")")
                self.name=self._strings_to_list(text[:end])
                text=text[end+1:]
            else:
                raise NotImplementedError("TODO")


        text = text.lstrip()

        if peekWord(text) == "DESC":
            text=text[len("DESC "):]
            text = text.lstrip()
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        text = text.lstrip()

        if peekWord(text) == "OBSOLETE":
            self.obsolete=1
            text=text[len("OBSOLETE "):]

        text = text.lstrip()

        if peekWord(text) == "SUP":
            text=text[len("SUP "):]
            text = text.lstrip()
            if text[0]=="(":
                text=text[1:]
                text = text.lstrip()
                end=text.index(")")
                self.sup=self._to_list(text[:end])
                text=text[end+1:]
            else:
                s, text = extractWord(text)
                self.sup=[s]

        text = text.lstrip()

        if peekWord(text) == "ABSTRACT":
            assert self.type is None
            self.type="ABSTRACT"
            text=text[len("ABSTRACT "):]

        text = text.lstrip()

        if peekWord(text) == "STRUCTURAL":
            assert self.type is None
            self.type="STRUCTURAL"
            text=text[len("STRUCTURAL "):]

        text = text.lstrip()

        if peekWord(text) == "AUXILIARY":
            assert self.type is None
            self.type="AUXILIARY"
            text=text[len("AUXILIARY "):]

        text = text.lstrip()

        if peekWord(text) == "MUST":
            text=text[len("MUST "):]
            text = text.lstrip()
            if text[0]=="(":
                text=text[1:]
                text = text.lstrip()
                end=text.index(")")
                self.must.extend(self._to_list(text[:end]))
                text=text[end+1:]
            else:
                s, text = extractWord(text)
                self.must.append(s)

        text = text.lstrip()

        if peekWord(text) == "MAY":
            text=text[len("MAY "):]
            text = text.lstrip()
            if text[0]=="(":
                text=text[1:]
                text = text.lstrip()
                end=text.index(")")
                self.may.extend(self._to_list(text[:end]))
                text=text[end+1:]
            else:
                s, text = extractWord(text)
                self.may.append(s)

        text = text.lstrip()

        assert text=="", "Text was not empty: %s"%repr(text)

        if not self.type:
            self.type="STRUCTURAL"

        assert self.oid
        for c in self.oid:
            assert c in "0123456789."
        assert self.name is None or self.name
        assert self.type in ("ABSTRACT", "STRUCTURAL", "AUXILIARY")

    def __repr__(self):
        nice = {}
        for k,v in self.__dict__.items():
            nice[k]=repr(v)
        return ("<%s instance at 0x%x"%(self.__class__.__name__, id(self))
                +(" oid=%(oid)s name=%(name)s desc=%(desc)s"
                  +" obsolete=%(obsolete)s sup=%(sup)s type=%(type)s"
                  +" must=%(must)s may=%(may)s>")%nice)

    def __str__(self):
        r=[]
        if self.name is not None:
            r.append('NAME %s' % self._str_list(self.name))
        if self.desc is not None:
            r.append('DESC %s' % self._str(self.desc))
        if self.obsolete:
            r.append('OBSOLETE')
        if self.sup:
            r.append('SUP %s' % self._list(self.sup))
        r.append('%s' % self.type)
        if self.must:
            r.append('MUST %s' % self._list(self.must))
        if self.may:
            r.append('MAY %s' % self._list(self.may))
        return ('( %s ' % self.oid
                + '\n        '.join(r)
                + ' )')

    def __lt__(self, other):
        if not isinstance(other, ObjectClassDescription):
            return NotImplemented
        if self.name is not None and other.name is not None:
            return self.name[0].upper() < other.name[0].upper()
        else:
            return self.oid < other.oid

    def __gt__(self, other):
        if not isinstance(other, ObjectClassDescription):
            return NotImplemented
        if self.name is not None and other.name is not None:
            return self.name[0].upper() > other.name[0].upper()
        else:
            return self.oid > other.oid

    def __le__(self, other):
        return self == other or self < other

    def __ge__(self, other):
        return self == other or self > other

    def __eq__(self, other):
        if not isinstance(other, ObjectClassDescription):
            return NotImplemented
        return (self.oid == other.oid
                and self.name == other.name
                and self.desc == other.desc
                and self.obsolete == other.obsolete
                and self.sup == other.sup
                and self.type == other.type
                and self.must == other.must
                and self.may == other.may)

    def __ne__(self, other):
        return not (self == other)

class AttributeTypeDescription(ASN1ParserThingie):
    """
    ASN Syntax::

        AttributeTypeDescription = "(" whsp
                numericoid whsp                ; AttributeType identifier
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
        self.sup=None
        self.equality=None
        self.ordering=None
        self.substr=None
        self.syntax=None
        self.single_value=None
        self.collective=None
        self.no_user_modification=None
        self.usage=None

        # storage for experimental terms ("X-SOMETHING"), so we can
        # output them when stringifying.
        self.x_attrs=[]

        if text is not None:
            self._parse(text)

    def _parse(self, text):
        assert text[0]=='(', "Text %s must be in parentheses."%repr(text)
        assert text[-1]==')', "Text %s must be in parentheses."%repr(text)
        text=text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "NAME":
            text=text[len("NAME "):]
            text = text.lstrip()
            if text[0]=="'":
                text=text[1:]
                end=text.index("'")
                self.name=(text[:end],)
                text=text[end+1:]
            elif text[0]=="(":
                text=text[1:]
                text = text.lstrip()
                end=text.index(")")
                self.name=self._strings_to_list(text[:end])
                text=text[end+1:]
            else:
                raise NotImplementedError("TODO")


        text = text.lstrip()

        if peekWord(text) == "DESC":
            text=text[len("DESC "):]
            text = text.lstrip()
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        text = text.lstrip()

        if peekWord(text) == "OBSOLETE":
            self.obsolete=1
            text=text[len("OBSOLETE "):]

        text = text.lstrip()

        if peekWord(text) == "SUP":
            text=text[len("SUP "):]
            text = text.lstrip()
            self.sup, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "EQUALITY":
            text=text[len("EQUALITY "):]
            text = text.lstrip()
            self.equality, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "ORDERING":
            text=text[len("ORDERING "):]
            text = text.lstrip()
            self.ordering, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "SUBSTR":
            text=text[len("SUBSTR "):]
            text = text.lstrip()
            self.substr, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "SYNTAX":
            text=text[len("SYNTAX "):]
            text = text.lstrip()
            self.syntax, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "SINGLE-VALUE":
            assert self.single_value is None
            self.single_value=1
            text=text[len("SINGLE-VALUE "):]

        text = text.lstrip()

        if peekWord(text) == "COLLECTIVE":
            assert self.collective is None
            self.collective=1
            text=text[len("COLLECTIVE "):]

        text = text.lstrip()

        if peekWord(text) == "NO-USER-MODIFICATION":
            assert self.no_user_modification is None
            self.no_user_modification=1
            text=text[len("NO-USER-MODIFICATION "):]

        text = text.lstrip()

        if peekWord(text) == "USAGE":
            assert self.usage is None
            text=text[len("USAGE "):]
            text = text.lstrip()
            self.usage, text = extractWord(text)


        while True:
            text = text.lstrip()

            word = peekWord(text)
            if word is None:
                break

            if word.startswith('X-'):
                text=text[len(word+" "):]
                text = text.lstrip()
                if text[0]=="'":
                    text=text[1:]
                    end=text.index("'")
                    value=text[:end]
                    text=text[end+1:]
                elif text[0]=="(":
                    text=text[1:]
                    text = text.lstrip()
                    end=text.index(")")
                    value=self._strings_to_list(text[:end])
                    text=text[end+1:]
                else:
                    raise NotImplementedError("TODO")

                self.x_attrs.append((word, value))
            else:
                raise RuntimeError('Unhandled attributeType: %r', word)

        assert text=="", "Text was not empty: %s"%repr(text)

        if self.single_value is None:
            self.single_value=0

        if self.collective is None:
            self.collective=0

        if self.no_user_modification is None:
            self.no_user_modification=0

        assert self.oid
        for c in self.oid:
            assert c in "0123456789."
        assert self.name is None or self.name
        assert self.usage is None or self.usage in (
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

    def __str__(self):
        r=[]
        if self.name is not None:
            r.append('NAME %s' % self._str_list(self.name))
        if self.desc is not None:
            r.append('DESC %s' % self._str(self.desc))
        if self.obsolete:
            r.append('OBSOLETE')
        if self.sup is not None:
            r.append('SUP %s' % self.sup)
        if self.equality is not None:
            r.append('EQUALITY %s' % self.equality)
        if self.ordering is not None:
            r.append('ORDERING %s' % self.ordering)
        if self.substr is not None:
            r.append('SUBSTR %s' % self.substr)
        if self.syntax is not None:
            r.append('SYNTAX %s' % self.syntax)
        if self.single_value:
            r.append('SINGLE-VALUE')
        if self.collective:
            r.append('COLLECTIVE')
        if self.no_user_modification:
            r.append('NO-USER-MODIFICATION')
        if self.usage is not None:
            r.append('USAGE %s' % self.usage)
        for name, value in self.x_attrs:
            if isinstance(value, basestring):
                r.append("%s '%s'" % (name, value))
            else:
                r.append(
                    '%s ( %s )' % (
                        name,
                        ' '.join("'%s'" % s for s in value),
                        ),
                    )
        return ('( %s ' % self.oid
                + '\n        '.join(r)
                + ' )')

class SyntaxDescription(ASN1ParserThingie):
    """
    ASN Syntax::

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
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "DESC":
            text=text[len("DESC "):]
            text = text.lstrip()
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        text = text.lstrip()

        if peekWord(text) == "X-BINARY-TRANSFER-REQUIRED":
            text=text[len("X-BINARY-TRANSFER-REQUIRED "):]
            text = text.lstrip()
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        text = text.lstrip()

        if peekWord(text) == "X-NOT-HUMAN-READABLE":
            text=text[len("X-NOT-HUMAN-READABLE "):]
            text = text.lstrip()
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        text = text.lstrip()

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
    ASN Syntax::

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
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == "NAME":
            text=text[len("NAME "):]
            text = text.lstrip()
            if text[0]=="'":
                text=text[1:]
                end=text.index("'")
                self.name=(text[:end],)
                text=text[end+1:]
            elif text[0]=="(":
                text=text[1:]
                text = text.lstrip()
                end=text.index(")")
                self.name=self._strings_to_list(text[:end])
                text=text[end+1:]
            else:
                raise NotImplementedError("TODO")

        text = text.lstrip()

        if peekWord(text) == "DESC":
            text=text[len("DESC "):]
            text = text.lstrip()
            assert text[0]=="'"
            text=text[1:]
            end=text.index("'")
            self.desc=text[:end]
            text=text[end+1:]

        text = text.lstrip()

        if peekWord(text) == "OBSOLETE":
            self.obsolete=1
            text=text[len("OBSOLETE "):]

        text = text.lstrip()

        if peekWord(text) == "SYNTAX":
            text=text[len("SYNTAX "):]
            text = text.lstrip()
            self.syntax, text = extractWord(text)

        text = text.lstrip()

        assert text=="", "Text was not empty: %s"%repr(text)

        if self.obsolete is None:
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
