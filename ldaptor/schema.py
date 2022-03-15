from ldaptor._encoder import WireStrAlias, to_bytes


def extractWord(text):
    if not text:
        return b"", b""
    l = text.split(None, 1)
    word = l[0]
    try:
        text = l[1]
    except IndexError:
        text = b""
    return word, text


def peekWord(text):
    if not text:
        return None
    return text.split(None, 1)[0]


class ASN1ParserThingie:
    def _to_list(self, text):
        """Split text into $-separated list."""
        r = []
        for x in text.split(b"$"):
            x = x.strip()
            assert x
            r.append(x)
        return tuple(r)

    def _strings_to_list(self, text):
        """Split ''-quoted strings into list."""
        r = []
        while text:
            text = text.lstrip()
            if not text:
                break
            assert text[:1] == b"'", "Text %s must start with a single quote." % repr(
                text
            )
            text = text[1:]
            end = text.index(b"'")
            r.append(text[:end])
            text = text[end + 1 :]
        return tuple(r)

    def _str_list(self, l):
        s = b" ".join([self._str(x) for x in l])
        if len(l) > 1:
            s = b"( %s )" % s
        return s

    def _list(self, l):
        s = b" $ ".join([x for x in l])
        if len(l) > 1:
            s = b"( %s )" % s
        return s

    def _str(self, s):
        return b"'%s'" % s


class ObjectClassDescription(ASN1ParserThingie, WireStrAlias):
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
        self.oid = None
        self.name = None
        self.desc = None
        self.obsolete = 0
        self.sup = []
        self.type = None
        self.must = []
        self.may = []

        if text is not None:
            self._parse(to_bytes(text))

    def _parse(self, text):
        assert text[:1] == b"(", "Text %s must be in parentheses." % repr(text)
        assert text[-1:] == b")", "Text %s must be in parentheses." % repr(text)
        text = text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"NAME":
            text = text[len(b"NAME ") :]
            text = text.lstrip()
            if text[:1] == b"'":
                text = text[1:]
                end = text.index(b"'")
                self.name = (text[:end],)
                text = text[end + 1 :]
            elif text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.name = self._strings_to_list(text[:end])
                text = text[end + 1 :]
            else:
                raise AssertionError()

        text = text.lstrip()

        if peekWord(text) == b"DESC":
            text = text[len(b"DESC ") :]
            text = text.lstrip()
            assert text[:1] == b"'"
            text = text[1:]
            end = text.index(b"'")
            self.desc = text[:end]
            text = text[end + 1 :]

        text = text.lstrip()

        if peekWord(text) == b"OBSOLETE":
            self.obsolete = 1
            text = text[len(b"OBSOLETE ") :]

        text = text.lstrip()

        if peekWord(text) == b"SUP":
            text = text[len(b"SUP ") :]
            text = text.lstrip()
            if text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.sup = self._to_list(text[:end])
                text = text[end + 1 :]
            else:
                s, text = extractWord(text)
                self.sup = [s]

        text = text.lstrip()

        if peekWord(text) == b"ABSTRACT":
            assert self.type is None
            self.type = b"ABSTRACT"
            text = text[len(b"ABSTRACT ") :]

        text = text.lstrip()

        if peekWord(text) == b"STRUCTURAL":
            assert self.type is None
            self.type = b"STRUCTURAL"
            text = text[len(b"STRUCTURAL ") :]

        text = text.lstrip()

        if peekWord(text) == b"AUXILIARY":
            assert self.type is None
            self.type = b"AUXILIARY"
            text = text[len(b"AUXILIARY ") :]

        text = text.lstrip()

        if peekWord(text) == b"MUST":
            text = text[len(b"MUST ") :]
            text = text.lstrip()
            if text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.must.extend(self._to_list(text[:end]))
                text = text[end + 1 :]
            else:
                s, text = extractWord(text)
                self.must.append(s)

        text = text.lstrip()

        if peekWord(text) == b"MAY":
            text = text[len(b"MAY ") :]
            text = text.lstrip()
            if text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.may.extend(self._to_list(text[:end]))
                text = text[end + 1 :]
            else:
                s, text = extractWord(text)
                self.may.append(s)

        text = text.lstrip()

        assert text == b"", "Text was not empty: %s" % repr(text)

        if not self.type:
            self.type = b"STRUCTURAL"

        assert self.oid
        for c in self.oid:
            assert c in b"0123456789."
        assert self.name is None or self.name
        assert self.type in (b"ABSTRACT", b"STRUCTURAL", b"AUXILIARY")

    def __repr__(self):
        nice = {}
        for k, v in self.__dict__.items():
            nice[k] = repr(v)
        return (
            f"<{self.__class__.__name__} instance at 0x{id(self):x}"
            + (
                " oid=%(oid)s name=%(name)s desc=%(desc)s"
                + " obsolete=%(obsolete)s sup=%(sup)s type=%(type)s"
                + " must=%(must)s may=%(may)s>"
            )
            % nice
        )

    def toWire(self):
        r = []
        if self.name is not None:
            r.append(b"NAME %s" % self._str_list(self.name))
        if self.desc is not None:
            r.append(b"DESC %s" % self._str(self.desc))
        if self.obsolete:
            r.append(b"OBSOLETE")
        if self.sup:
            r.append(b"SUP %s" % self._list(self.sup))
        r.append(b"%s" % self.type)
        if self.must:
            r.append(b"MUST %s" % self._list(self.must))
        if self.may:
            r.append(b"MAY %s" % self._list(self.may))
        return b"( %s " % self.oid + b"\n        ".join(r) + b" )"

    def __lt__(self, other):
        if not isinstance(other, ObjectClassDescription):
            raise NotImplementedError()
        if self.name is not None and other.name is not None:
            return self.name[0].upper() < other.name[0].upper()
        else:
            return self.oid < other.oid

    def __gt__(self, other):
        if not isinstance(other, ObjectClassDescription):
            raise NotImplementedError()
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
            raise NotImplementedError()
        return (
            self.oid == other.oid
            and self.name == other.name
            and self.desc == other.desc
            and self.obsolete == other.obsolete
            and self.sup == other.sup
            and self.type == other.type
            and self.must == other.must
            and self.may == other.may
        )

    def __ne__(self, other):
        return not (self == other)


class AttributeTypeDescription(ASN1ParserThingie, WireStrAlias):
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
        self.oid = None
        self.name = None
        self.desc = None
        self.obsolete = 0
        self.sup = None
        self.equality = None
        self.ordering = None
        self.substr = None
        self.syntax = None
        self.single_value = None
        self.collective = None
        self.no_user_modification = None
        self.usage = None

        # storage for experimental terms ("X-SOMETHING"), so we can
        # output them when stringifying.
        self.x_attrs = []

        if text is not None:
            self._parse(to_bytes(text))

    def _parse(self, text):
        assert text[:1] == b"(", "Text %s must be in parentheses." % repr(text)
        assert text[-1:] == b")", "Text %s must be in parentheses." % repr(text)
        text = text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"NAME":
            text = text[len(b"NAME ") :]
            text = text.lstrip()
            if text[:1] == b"'":
                text = text[1:]
                end = text.index(b"'")
                self.name = (text[:end],)
                text = text[end + 1 :]
            elif text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.name = self._strings_to_list(text[:end])
                text = text[end + 1 :]
            else:
                raise AssertionError()

        text = text.lstrip()

        if peekWord(text) == b"DESC":
            text = text[len(b"DESC ") :]
            text = text.lstrip()
            assert text[:1] == b"'"
            text = text[1:]
            end = text.index(b"'")
            self.desc = text[:end]
            text = text[end + 1 :]

        text = text.lstrip()

        if peekWord(text) == b"OBSOLETE":
            self.obsolete = 1
            text = text[len(b"OBSOLETE ") :]

        text = text.lstrip()

        if peekWord(text) == b"SUP":
            text = text[len(b"SUP ") :]
            text = text.lstrip()
            self.sup, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"EQUALITY":
            text = text[len(b"EQUALITY ") :]
            text = text.lstrip()
            self.equality, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"ORDERING":
            text = text[len(b"ORDERING ") :]
            text = text.lstrip()
            self.ordering, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"SUBSTR":
            text = text[len(b"SUBSTR ") :]
            text = text.lstrip()
            self.substr, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"SYNTAX":
            text = text[len(b"SYNTAX ") :]
            text = text.lstrip()
            self.syntax, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"SINGLE-VALUE":
            assert self.single_value is None
            self.single_value = 1
            text = text[len(b"SINGLE-VALUE ") :]

        text = text.lstrip()

        if peekWord(text) == b"COLLECTIVE":
            assert self.collective is None
            self.collective = 1
            text = text[len(b"COLLECTIVE ") :]

        text = text.lstrip()

        if peekWord(text) == b"NO-USER-MODIFICATION":
            assert self.no_user_modification is None
            self.no_user_modification = 1
            text = text[len(b"NO-USER-MODIFICATION ") :]

        text = text.lstrip()

        if peekWord(text) == b"USAGE":
            assert self.usage is None
            text = text[len(b"USAGE ") :]
            text = text.lstrip()
            self.usage, text = extractWord(text)

        while True:
            text = text.lstrip()

            word = peekWord(text)
            if word is None:
                break

            if word.startswith(b"X-"):
                text = text[len(word + b" ") :]
                text = text.lstrip()
                if text[:1] == b"'":
                    text = text[1:]
                    end = text.index(b"'")
                    value = text[:end]
                    text = text[end + 1 :]
                elif text[:1] == b"(":
                    text = text[1:]
                    text = text.lstrip()
                    end = text.index(b")")
                    value = self._strings_to_list(text[:end])
                    text = text[end + 1 :]
                else:
                    raise AssertionError()

                self.x_attrs.append((word, value))
            else:
                raise AssertionError("Unhandled attributeType: %r", word)

        assert text == b"", "Text was not empty: %s" % repr(text)

        if self.single_value is None:
            self.single_value = 0

        if self.collective is None:
            self.collective = 0

        if self.no_user_modification is None:
            self.no_user_modification = 0

        assert self.oid
        for c in self.oid:
            assert c in b"0123456789."
        assert self.name is None or self.name
        assert self.usage is None or self.usage in (
            b"userApplications",
            b"directoryOperation",
            b"distributedOperation",
            b"dSAOperation",
        )

    def __repr__(self):
        nice = {}
        for k, v in self.__dict__.items():
            nice[k] = repr(v)
        return (
            f"<{self.__class__.__name__} instance at 0x{id(self):x}"
            + (
                " oid=%(oid)s name=%(name)s desc=%(desc)s"
                + " obsolete=%(obsolete)s sup=%(sup)s"
                + " equality=%(equality)s ordering=%(ordering)s"
                + " substr=%(substr)s syntax=%(syntax)s"
                + " single_value=%(single_value)s"
                + " collective=%(collective)s"
                + " no_user_modification=%(no_user_modification)s"
                + " usage=%(usage)s>"
            )
            % nice
        )

    def toWire(self):
        r = []
        if self.name is not None:
            r.append(b"NAME %s" % self._str_list(self.name))
        if self.desc is not None:
            r.append(b"DESC %s" % self._str(self.desc))
        if self.obsolete:
            r.append(b"OBSOLETE")
        if self.sup is not None:
            r.append(b"SUP %s" % self.sup)
        if self.equality is not None:
            r.append(b"EQUALITY %s" % self.equality)
        if self.ordering is not None:
            r.append(b"ORDERING %s" % self.ordering)
        if self.substr is not None:
            r.append(b"SUBSTR %s" % self.substr)
        if self.syntax is not None:
            r.append(b"SYNTAX %s" % self.syntax)
        if self.single_value:
            r.append(b"SINGLE-VALUE")
        if self.collective:
            r.append(b"COLLECTIVE")
        if self.no_user_modification:
            r.append(b"NO-USER-MODIFICATION")
        if self.usage is not None:
            r.append(b"USAGE %s" % self.usage)
        for name, value in self.x_attrs:
            if isinstance(value, (bytes, str)):
                r.append(b"%s '%s'" % (name, value))
            else:
                r.append(
                    b"%s ( %s )"
                    % (
                        name,
                        b" ".join(b"'%s'" % s for s in value),
                    ),
                )
        return b"( %s " % self.oid + b"\n        ".join(r) + b" )"


class SyntaxDescription(ASN1ParserThingie, WireStrAlias):
    """
    ASN Syntax::

        SyntaxDescription = "(" whsp
                numericoid whsp
                [ "DESC" qdstring ]
                whsp ")"
    """

    def __init__(self, text):
        self.oid = None
        self.desc = None
        self.binary_transfer_required = False
        self.human_readable = True

        if text is not None:
            self._parse(to_bytes(text))

    def _parse(self, text):

        assert text[:1] == b"("
        assert text[-1:] == b")"
        text = text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"DESC":
            text = text[len(b"DESC ") :]
            text = text.lstrip()
            assert text[:1] == b"'"
            text = text[1:]
            end = text.index(b"'")
            self.desc = text[:end]
            text = text[end + 1 :]

        text = text.lstrip()

        if peekWord(text) == b"X-BINARY-TRANSFER-REQUIRED":
            self.binary_transfer_required = True
            text = text[len(b"X-BINARY-TRANSFER-REQUIRED 'TRUE' ") :]
            text = text.lstrip()

        text = text.lstrip()

        if peekWord(text) == b"X-NOT-HUMAN-READABLE":
            self.human_readable = False
            text = text[len(b"X-NOT-HUMAN-READABLE 'TRUE' ") :]
            text = text.lstrip()

        text = text.lstrip()

        assert text == b"", "Text was not empty: %s" % repr(text)

        assert self.oid
        for c in self.oid:
            assert c in b"0123456789."

    def toWire(self):
        r = [self.oid]

        if self.desc is not None:
            r.append(b"DESC %s" % self._str(self.desc))
        if self.binary_transfer_required is True:
            r.append(b"X-BINARY-TRANSFER-REQUIRED 'TRUE'")
        if self.human_readable is False:
            r.append(b"X-NOT-HUMAN-READABLE 'TRUE'")

        return b"( " + b" ".join(r) + b" )"

    def __repr__(self):
        nice = {}
        for k, v in self.__dict__.items():
            nice[k] = repr(v)
        return (
            f"<{self.__class__.__name__} instance at 0x{id(self):x}"
            + (" oid=%(oid)s desc=%(desc)s>") % nice
        )


class MatchingRuleDescription(ASN1ParserThingie, WireStrAlias):
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
        self.oid = None
        self.name = None
        self.desc = None
        self.obsolete = None
        self.syntax = None

        if text is not None:
            self._parse(to_bytes(text))

    def _parse(self, text):

        assert text[:1] == b"("
        assert text[-1:] == b")"
        text = text[1:-1]
        text = text.lstrip()

        # oid
        self.oid, text = extractWord(text)

        text = text.lstrip()

        if peekWord(text) == b"NAME":
            text = text[len(b"NAME ") :]
            text = text.lstrip()
            if text[:1] == b"'":
                text = text[1:]
                end = text.index(b"'")
                self.name = (text[:end],)
                text = text[end + 1 :]
            elif text[:1] == b"(":
                text = text[1:]
                text = text.lstrip()
                end = text.index(b")")
                self.name = self._strings_to_list(text[:end])
                text = text[end + 1 :]
            else:
                raise AssertionError()

        text = text.lstrip()

        if peekWord(text) == b"DESC":
            text = text[len(b"DESC ") :]
            text = text.lstrip()
            assert text[:1] == b"'"
            text = text[1:]
            end = text.index(b"'")
            self.desc = text[:end]
            text = text[end + 1 :]

        text = text.lstrip()

        if peekWord(text) == b"OBSOLETE":
            self.obsolete = 1
            text = text[len(b"OBSOLETE ") :]

        text = text.lstrip()

        if peekWord(text) == b"SYNTAX":
            text = text[len(b"SYNTAX ") :]
            text = text.lstrip()
            self.syntax, text = extractWord(text)

        text = text.lstrip()

        assert text == b"", "Text was not empty: %s" % repr(text)

        if self.obsolete is None:
            self.obsolete = 0
        assert self.oid
        for c in self.oid:
            assert c in b"0123456789."
        assert self.syntax

    def toWire(self):
        r = [self.oid]

        if self.name is not None:
            r.append(b"NAME %s" % self._str_list(self.name))
        if self.desc is not None:
            r.append(b"DESC %s" % self._str(self.desc))
        if self.obsolete:
            r.append(b"OBSOLETE")
        r.append(b"SYNTAX %s" % self.syntax)

        return b"( " + b" ".join(r) + b" )"

    def __repr__(self):
        nice = {}
        for k, v in self.__dict__.items():
            nice[k] = repr(v)
        return (
            f"<{self.__class__.__name__} instance at 0x{id(self):x}"
            + (" oid=%(oid)s desc=%(desc)s>") % nice
        )
