"""Helper functions for HTMLization of LDAP objects."""

def htmlify_attributes(attributes):
    result='<ul>\n'
    for a,l in attributes:
	if len(l)==0:
	    result=result+"  <li>%s: <i>none</i>\n"%a
	elif len(l)==1:
            for attr in l:
                first = attr
                break
	    result=result+"  <li>%s: %s\n"%(a, first)
	else:
	    result=result+"  <li>%s:\n    <ul>\n"%a
	    for i in l:
		result=result+"      <li>%s\n"%i
	    result=result+"    </ul>\n"

    result=result+"</ul>\n"
    return result

def htmlify_object(o):
    result='<b>'+str(o.dn)+'</b>'
    result+='<ul>\n'

    for a in o.keys():
        l=o[a]
	if len(l)==0:
	    result=result+"  <li>%s: <i>none</i>\n"%a
	elif len(l)==1:
            for x in l:
                result=result+"  <li>%s: %s\n"%(a, x)
	else:
	    result=result+"  <li>%s:\n    <ul>\n"%a
	    for i in l:
		result=result+"      <li>%s\n"%i
	    result=result+"    </ul>\n"

    result=result+"</ul>\n"
    return result
