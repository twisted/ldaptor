"""Helper functions for HTMLization of LDAP objects."""

def htmlify_attributes(attributes):
    result='<ul>\n'
    for a,l in attributes:
        if len(l)==0:
            result=result+"  <li>%s: <i>none</i>\n"%a
        elif len(l)==1:
            result=result+"  <li>%s: %s\n"%(a, l[0])
        else:
            result=result+"  <li>%s:\n    <ul>\n"%a
            for i in l:
                result=result+"      <li>%s\n"%i
            result=result+"    </ul>\n"

    result=result+"</ul>\n"
    return result
