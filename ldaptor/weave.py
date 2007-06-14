from zope.interface import Interface, implements
from twisted.python import components
from nevow import tags, inevow, flat
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor import interfaces

def keyvalue(context, data):
    """
    Render items in a mapping using patterns found in the children
    of the element.

    Keyvalue recognizes the following patterns:

      - header: Rendered at the start, before the first item. If
        multiple header patterns are provided they are rendered
        together in the order they were defined.

      - footer: Just like the header only renderer at the end, after
        the last item.

      - item: Rendered once for each item in the sequence. Can contain
        subpatterns key and value.

        If multiple item patterns are provided then the pattern is
        cycled in the order defined.

      - divider: Rendered once between each item in the
        sequence. Multiple divider patterns are cycled.

      - empty: Rendered instead of item and divider patterns when the
        sequence contains no items.

    Example::

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
    headers = context.tag.allPatterns('header')
    item = context.tag.patternGenerator('item')
    divider = context.tag.patternGenerator('divider', default=tags.invisible)
    content = []
    for key, value in data.items():
        content.append(item(data=(key, value)))
        content.append(divider(data=(key, value)))
    if not content:
        content = context.tag.allPatterns('empty')
    else:
        ## No divider after the last thing.
        del content[-1]
    footers = context.tag.allPatterns('footer')
    return context.tag.clear()[ headers, content, footers ]

def keyvalue_item(context, data):
    key, value = data

    k = context.tag.patternGenerator('key')
    v = context.tag.patternGenerator('value')

    return context.tag.clear()[ k(data=key), v(data=value) ]

class _DictLike(object):
    implements(inevow.IContainer)

    def __init__(self, original):
        self.original = original

    def child(self, context, name):
        return self.original.get(name, None)

    def items(self):
        return self.original.items()

class LDAPEntryContainer(object):
    implements(inevow.IContainer)

    def __init__(self, original):
        self.original = original

    def child(self, context, name):
        if name == 'dn':
            return self.original.dn
        elif name == 'attributes':
            return _DictLike(self.original)
        else:
            return None

components.registerAdapter(
    LDAPEntryContainer,
    ldapsyntax.LDAPEntryWithClient,
    inevow.IContainer)

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

class IZebraStyle(Interface):
    """Marker interface for zebra."""
    pass

def zebra(styles=['zebra-odd', 'zebra-even']):
    """
    Provide alternating background colors for e.g. zebra tables.

    @param styles: Two or more CSS class names to iterate.

    Use like this::

      render_zebra = weave.zebra()

      <table>
        <tr nevow:render="zebra"><td>foo</td></tr>
        <tr nevow:render="zebra"><td>bar</td></tr>
        <tr nevow:render="zebra"><td>baz</td></tr>
      </table>
    """
    styles = list(styles)
    def f(self, ctx, data):
        request = inevow.IRequest(ctx)
        state = IZebraStyle(request, styles)
        r = ctx.tag(class_="%s" % state[0])
        request.setComponent(IZebraStyle, state[1:]+state[:1])

        return r
    return f
