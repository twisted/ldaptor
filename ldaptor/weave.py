from nevow import tags, compy, inevow, flat
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor import interfaces

def keyvalue(context, data):
    """
    Render items in a mapping using patterns found in the children
    of the element.
    
    Keyvalue recognizes the following patterns:

    header: Rendered at the start, before the first item. If multiple
        header patterns are provided they are rendered together in the
        order they were defined.
            
    footer: Just like the header only renderer at the end, after the
        last item.
    
    item: Rendered once for each item in the sequence. Can contain
        subpatterns key and value.

        If multiple item patterns are provided then the pattern is
        cycled in the order defined.
        
    divider: Rendered once between each item in the sequence. Multiple
        divider patterns are cycled.

    empty: Rendered instead of item and divider patterns when the
        sequence contains no items.

    Example:
    
    <table nevow:render="sequence" nevow:data="peopleSeq">
      <tr nevow:pattern="header">
        <th>name</th>
        <th>email</th>
      </tr>
      <tr nevow:pattern="item" class="odd">
        <td>name goes here</td>
        <td>email goes here</td>
      </tr>
      <tr nevow:pattern="item" class="even">
        <td>name goes here</td>
        <td>email goes here</td>
      </tr>
      <tr nevow:pattern="empty">
        <td colspan="2"><em>they've all gone!</em></td>
      </tr>
    </table>

    """
    headers = context.allPatterns('header')
    item = context.patternGenerator('item')
    divider = context.patternGenerator('divider', default=tags.invisible)
    content = []
    for key, value in data.items():
        content.append(item(data=(key, value)))
        content.append(divider(data=(key, value)))
    if not content:
        content = context.allPatterns('empty')
    else:
        ## No divider after the last thing.
        del content[-1]
    footers = context.allPatterns('footer')
    return context.tag.clear()[ headers, content, footers ]

def keyvalue_item(context, data):
    key, value = data

    k = context.patternGenerator('key')
    v = context.patternGenerator('value')

    return context.tag.clear()[ k(data=key), v(data=value) ]

class LDAPEntryContainer(object):
    __implements__ = inevow.IContainer

    def __init__(self, original):
        self.original = original

    def child(self, context, name):
        if name == 'dn':
            return self.original.dn
        elif name == 'attributes':
            return self.original
        else:
            return None

compy.registerAdapter(LDAPEntryContainer, ldapsyntax.LDAPEntryWithClient, inevow.IContainer)

def dnSerializer(original, context):
    return flat.serialize(str(original), context)

flat.registerFlattener(dnSerializer,
                       distinguishedname.DistinguishedName)

def entrySerializer(original, context):
    ul = tags.ul()
    for a,l in original.items():
	if len(l)==0:
	    ul[tags.li[a, ': none']]
	elif len(l)==1:
            for attr in l:
                first = attr
                break
	    ul[tags.li[a, ': ', first]]
	else:
            li=tags.li[a, ':']
            ul[li]
            liul=tags.ul()
            li[liul]
	    for i in l:
		liul[tags.li[i]]
    return flat.serialize(ul, context)

flat.registerFlattener(entrySerializer,
                       interfaces.ILDAPEntry)
