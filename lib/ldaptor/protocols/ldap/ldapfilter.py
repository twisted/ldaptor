#!/usr/bin/python

from ldaptor.protocols import pureldap

"""

RFC2254:

        filter     = "(" filtercomp ")"
        filtercomp = and / or / not / item
        and        = "&" filterlist
        or         = "|" filterlist
        not        = "!" filter
        filterlist = 1*filter
        item       = simple / present / substring / extensible
        simple     = attr filtertype value
        filtertype = equal / approx / greater / less
        equal      = "="
        approx     = "~="
        greater    = ">="
        less       = "<="
        extensible = attr [":dn"] [":" matchingrule] ":=" value
                     / [":dn"] ":" matchingrule ":=" value
        present    = attr "=*"
        substring  = attr "=" [initial] any [final]
        initial    = value
        any        = "*" *(value "*")
        final      = value
        attr       = AttributeDescription from Section 4.1.5 of [1]
        matchingrule = MatchingRuleId from Section 4.1.9 of [1]
        value      = AttributeValue from Section 4.1.6 of [1]
"""

class InvalidLDAPFilter(Exception):
    def __init__(self, syntax, value):
        Exception.__init__(self)
        self.syntax=syntax
        self.value=value

    def __str__(self):
        return "Invalid LDAP filter, syntax type %s, value %s" \
               % (self.syntax, repr(self.value))

"""

        extensible = attr [":dn"] [":" matchingrule] ":=" value
                     / [":dn"] ":" matchingrule ":=" value

        substring  = attr "=" [initial] any [final]
        initial    = value
        any        = "*" *(value "*")
        final      = value

        attr       = AttributeDescription from Section 4.1.5 of [1]
        matchingrule = MatchingRuleId from Section 4.1.9 of [1]
        value      = AttributeValue from Section 4.1.6 of [1]
"""
        
def parseEqual(attr, s):
    return pureldap.LDAPFilter_equalityMatch(
        attributeDesc=pureldap.LDAPAttributeDescription(attr),
        assertionValue=pureldap.LDAPAssertionValue(s))

def parseExtensible(attr, s):
    raise NotImplementedError

def parsePresent(attr):
    return pureldap.LDAPFilter_present(attr)

def parseSubstring(attr, s):
    # TODO this most likely isn't correct
    l=[]
    substrings = s.split('*')
    first=substrings[0]
    del substrings[0]
    last=substrings[-1]
    del substrings[-1]

    if first!='':
        l.append(pureldap.LDAPFilter_substrings_initial(first))

    for x in substrings:
        l.append(pureldap.LDAPFilter_substrings_any(x))

    if last!='':
        l.append(pureldap.LDAPFilter_substrings_final(last))
    
    return pureldap.LDAPFilter_substrings(
        type=attr,
        substrings=l)

def parseApprox(attr, s):
    return pureldap.LDAPFilter_approxMatch(
        attributeDesc=pureldap.LDAPAttributeDescription(attr),
        assertionValue=pureldap.LDAPAssertionValue(s))

def parseGreater(attr, s):
    return pureldap.LDAPFilter_greaterOrEqual(
        attributeDesc=pureldap.LDAPAttributeDescription(attr),
        assertionValue=pureldap.LDAPAssertionValue(s))

def parseLess(attr, s):
    return pureldap.LDAPFilter_lessOrEqual(
        attributeDesc=pureldap.LDAPAttributeDescription(attr),
        assertionValue=pureldap.LDAPAssertionValue(s))


def parseItem(s):
    i=0
    while i<len(s):
        #TODO what chars can attributes contain?
        if s[i] not in \
           "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
            break
        i+=1

    attr=s[:i]
    s=s[i:]

    if s=="=*":
        return parsePresent(attr)
    elif s.startswith("="):
        if s.find("*")>=0:
            return parseSubstring(attr, s[1:])
        else:
            return parseEqual(attr, s[1:])
    elif s.startswith("~="):
        return parseApprox(attr, s[2:])
    elif s.startswith(">="):
        return parseGreater(attr, s[2:])
    elif s.startswith("<="):
        return parseLess(attr, s[2:])
    elif s.startswith(":"):
        return parseExtensible(attr, s[1:])
    else:
        raise InvalidLDAPFilter, ("item", attr+s)
        

def parseFilterlist(s):
    r=[]
    while s:
        if not s.startswith('(') or not s.endswith(')'):
            raise InvalidLDAPFilter, ("filterlist", s)
        level=0
        i=0
        while i<len(s):
            c=s[i]
            i+=1
            if c=='(':
                level+=1
            elif c==')':
                level-=1
            if level==0:
                r.append(parseFilter(s[:i]))
                s=s[i:]
                break
    return r
        

def parseFiltercomp(s):
    if s.startswith('&'):
        return pureldap.LDAPFilter_and(parseFilterlist(s[1:]))
    elif s.startswith('|'):
        return pureldap.LDAPFilter_or(parseFilterlist(s[1:]))
    elif s.startswith('!'):
        return pureldap.LDAPFilter_not(parseFilter(s[1:]))
    else:
        return parseItem(s)

def parseFilter(s):
    if not s.startswith('(') or not s.endswith(')'):
        raise InvalidLDAPFilter, ("filtercomp", s)
    return parseFiltercomp(s[1:-1])

if __name__=='__main__':
    import sys
    for filt in sys.argv[1:]:
        print repr(parseFilter(filt))
