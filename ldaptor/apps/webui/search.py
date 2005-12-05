from zope.interface import implements
from twisted.internet import defer
from twisted.python import components
from ldaptor.protocols.ldap import ldapclient, ldapsyntax
from ldaptor.protocols.ldap import distinguishedname, ldapconnector
from ldaptor.protocols import pureldap
from ldaptor import ldapfilter, interfaces
from twisted.internet import reactor
from ldaptor.apps.webui import config, iwebui
from ldaptor.apps.webui.uriquote import uriQuote
from ldaptor.apps.webui.i18n import _
from ldaptor.apps.webui import i18n
from ldaptor import weave

import os
from nevow import rend, inevow, loaders, url, tags
from formless import annotate, webform, iformless, configurable

class IMove(components.Interface):
    """Entries being moved in the tree."""
    pass

class IMoveItem(annotate.TypedInterface):
    def move(self,
             context=annotate.Context()):
        pass
    move = annotate.autocallable(move,
                                 label=_('Move'))

    def cancel(self,
               context=annotate.Context()):
        pass
    cancel = annotate.autocallable(cancel,
                                   label=_('Cancel'))

class MoveItem(object):
    implements(IMoveItem)

    def __init__(self, entry):
        super(MoveItem, self).__init__()
        self.entry = entry

    def _remove(self, context):
        session = context.locate(inevow.ISession)
        move = session.getComponent(IMove)
        if move is None:
            return
        try:
            move.remove(self.entry)
        except ValueError:
            pass

    def move(self, context):
        cfg = context.locate(interfaces.ILDAPConfig)
        newDN = distinguishedname.DistinguishedName(
            self.entry.dn.split()[:1]
            + iwebui.ICurrentDN(context).split())
        d = self.entry.move(newDN)
        d.addCallback(lambda dummy: _('Moved %s to %s.') % (self.entry.dn, newDN))
        def _cb(r, context):
            self._remove(context)
            return r
        d.addCallback(_cb, context)
        return d

    def cancel(self, context):
        self._remove(context)
        return _('Cancelled move of %s') % self.entry.dn

def strScope(scope):
    if scope == pureldap.LDAP_SCOPE_wholeSubtree:
        return _('whole subtree')
    elif scope == pureldap.LDAP_SCOPE_singleLevel:
        return _('single level')
    elif scope == pureldap.LDAP_SCOPE_baseObject:
        return _('baseobject')
    else:
        raise RuntimeError, 'scope is not known: %r' % scope

class SearchForm(configurable.Configurable):
    implements(inevow.IContainer)

    filter = None

    def __init__(self):
        super(SearchForm, self).__init__(None)
        self.data = {}

    def getBindingNames(self, ctx):
        return ['search']

    def bind_search(self, ctx):
        l = []
        l.append(annotate.Argument('ctx', annotate.Context()))
        for field in config.getSearchFieldNames():
            l.append(annotate.Argument('search_%s' % field,
                                       annotate.String(label=field)))
        l.append(annotate.Argument('searchfilter',
                                   annotate.String(label=_("Advanced search"))))
        l.append(annotate.Argument(
            'scope',
            annotate.Choice(label=_("Search depth"),
                            choices=[ pureldap.LDAP_SCOPE_wholeSubtree,
                                      pureldap.LDAP_SCOPE_singleLevel,
                                      pureldap.LDAP_SCOPE_baseObject,
                                      ],
                            stringify=strScope,
                            default=pureldap.LDAP_SCOPE_wholeSubtree)))

        return annotate.MethodBinding(
            name='search',
            action=_("Search"),
            typeValue=annotate.Method(arguments=l,
                                      label=_('Search')))

    def search(self, ctx, scope, searchfilter, **kw):
        filt=[]
        for k,v in kw.items():
            assert k.startswith('search_')
            if not k.startswith("search_"):
                continue
            k=k[len("search_"):]
            if v is None:
                continue
            v=v.strip()
            if v=='':
                continue

            # TODO escape ) in v
            # TODO handle unknown filter name right (old form open in browser etc)
            filter_ = config.getSearchFieldByName(k, vars={'input': v})
            filt.append(ldapfilter.parseFilter(filter_))
        if searchfilter:
            try:
                filt.append(ldapfilter.parseFilter(searchfilter))
            except ldapfilter.InvalidLDAPFilter, e:
                raise annotate.ValidateError(
                    {'searchfilter': str(e), },
                    partialForm=inevow.IRequest(ctx).args)

        if filt:
            if len(filt)==1:
                query=filt[0]
            else:
                query=pureldap.LDAPFilter_and(filt)
        else:
            query=pureldap.LDAPFilterMatchAll

        self.data.update(kw)

        # annotate.Choice in nevow 0.3 maps choices to a list, and
        # passes indexes to this list to client. annotate.Choice in
        # 0.4pre converts choice to string and back with callbacks,
        # defaulting to str, and leaving the value as string.  We
        # can't use the 0.4pre mechanism as long as we need 0.3
        # compatibility, so work around that by explicitly making sure
        # scope is an integer.
        scope = int(scope)

        self.data['scope'] = scope
        self.data['searchfilter'] = searchfilter
        self.filter = query
        return self

    def child(self, context, name):
        fn = getattr(self, 'child_%s' % name, None)
        if fn is None:
            return None
        else:
            return fn(context)

    def child_filter(self, context):
        return self.filter.asText()

    def child_results(self, context):
        assert self.filter is not None
        cfg = context.locate(interfaces.ILDAPConfig)

        c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        curDN = iwebui.ICurrentDN(context)
        d=c.connectAnonymously(curDN,
                               cfg.getServiceLocationOverrides())

        def _search(proto, dn, searchFilter, scope):
            baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=dn)
            d=baseEntry.search(filterObject=searchFilter,
                               scope=scope,
                               sizeLimit=20,
                               sizeLimitIsNonFatal=True)
            return d
        d.addCallback(_search, curDN, self.filter, self.data['scope'])
        return d

    def child_base(self, context):
        cfg = context.locate(interfaces.ILDAPConfig)

        c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        d=c.connectAnonymously(iwebui.ICurrentDN(context),
                               cfg.getServiceLocationOverrides())

        def _search(proto, base):
            baseEntry = ldapsyntax.LDAPEntry(client=proto,
                                             dn=base)
            d=baseEntry.search(scope=pureldap.LDAP_SCOPE_baseObject,
                               sizeLimit=1)
            return d
        d.addCallback(_search, iwebui.ICurrentDN(context))

        def _first(results, dn):
            assert len(results)==1, \
                   "Expected one result, not %r" % results
            return {'dn': dn,
                    'attributes': results[0],
                    }
        d.addCallback(_first, iwebui.ICurrentDN(context))

        return d

    def __nonzero__(self):
        return self.filter is not None

class SearchPage(rend.Page):
    addSlash = True

    docFactory = loaders.xmlfile(
        'search.xhtml',
        templateDir=os.path.split(os.path.abspath(__file__))[0])

    def __init__(self):
        super(SearchPage, self).__init__()

    def data_css(self, ctx, data):
        root = url.URL.fromContext(ctx).clear().parentdir().parentdir()
        return [
            root.child('form.css'),
            root.child('ldaptor.css'),
            ]

    def render_css_item(self, context, data):
        context.fillSlots('url', data)
        return context.tag

    def render_form(self, ctx, data):
        d = defer.maybeDeferred(self.locateConfigurable, ctx, '')
        def _cb(conf, ctx):
            formDefaults = ctx.locate(iformless.IFormDefaults)
            methodDefaults = formDefaults.getAllDefaults('search')
            for k,v in conf.data.items():
                if v is not None:
                    methodDefaults[k] = str(v)
            return webform.renderForms()
        d.addCallback(_cb, ctx)
        return d

    def render_keyvalue(self, context, data):
        return weave.keyvalue(context, data)

    def render_keyvalue_item(self, context, data):
        return weave.keyvalue_item(context, data)

    def render_passthrough(self, context, data):
        return context.tag.clear()[data]

    def data_status(self, context, data):
        try:
            obj = context.locate(inevow.IStatusMessage)
        except KeyError:
            return ''

        if isinstance(obj, SearchForm):
            return ''
        else:
            return obj

    def render_data(self, ctx, data):
        return ctx.tag.clear()[data]

    def render_if(self, context, data):
        r=context.tag.allPatterns(str(bool(data)))
        return context.tag.clear()[r]

    def configurable_(self, context):
        try:
            hand = context.locate(inevow.IHand)
        except KeyError:
            pass
        else:
            if isinstance(hand, SearchForm):
                return hand
        return SearchForm()

    def data_search(self, context, data):
        configurable = self.locateConfigurable(context, '')
        return configurable

    def data_header(self, ctx, data):
        u=url.URL.fromContext(ctx)
        u=u.parentdir()
        l=[]
        l.append(tags.a(href=u.sibling("add"))[_("add new entry")])
        return l

    def data_navilink(self, context, data):
        cfg = context.locate(interfaces.ILDAPConfig)
        dn = iwebui.ICurrentDN(context)

        r=[]
        while dn!=distinguishedname.DistinguishedName(stringValue=''): #TODO and while inside base?
            firstPart=dn.split()[0]
            r.append(('../../%s' % uriQuote(str(dn)),
                      str(firstPart)))
            dn=dn.up()
        return r

    def render_link(self, context, (url, desc)):
        context.fillSlots('url', url)
        context.fillSlots('description', desc)
        return context.tag

    def render_linkedDN(self, ctx, data):
        dn = data
        cfg = ctx.locate(interfaces.ILDAPConfig)
        baseDN = iwebui.ICurrentDN(ctx)

        ctx.tag.clear()
        while (dn!=baseDN
               and dn!=distinguishedname.DistinguishedName(stringValue='')):
            firstPart=dn.split()[0]

            u = url.here.parentdir().parentdir().child(dn)
            segments = inevow.ICurrentSegments(ctx)
            if segments[-1] == '':
                u = u.child(segments[-2]).child(segments[-1])
            else:
                u = u.child(segments[-1])
            for segment in inevow.IRemainingSegments(ctx):
                u = u.child(segment)
            ctx.tag[tags.a(href=u)[str(firstPart)], ',']
            dn=dn.up()

        ctx.tag['%s\n' % str(dn)]
        return ctx.tag

    def render_entryLinks(self, ctx, data):
        u = url.URL.fromContext(ctx)
        l = [ (u.parentdir().sibling('edit').child(uriQuote(data)),
               _('edit')),
              (u.parentdir().sibling('move').child(uriQuote(data)),
               _('move')),
              (u.parentdir().sibling('delete').child(uriQuote(data)),
               _('delete')),
              (u.parentdir().sibling('change_password').child(uriQuote(data)),
               _('change password')),
              ]
        return self.render_sequence(ctx, l)

    def render_listLen(self, context, data):
        if data is None:
            length = 0
        else:
            length = len(data)
            return context.tag.clear()[length]

    def render_mass_change_password(self, ctx, data):
        u = url.URL.fromContext(ctx)
        u = u.parentdir().sibling("mass_change_password")
        u = u.child(uriQuote(data))
        return ctx.tag(href=u)

    def data_move(self, context, data):
        session = context.locate(inevow.ISession)
        if not session.getLoggedInRoot().loggedIn:
            return []
        move = session.getComponent(IMove)
        if move is None:
            return []
        return move

    def locateConfigurable(self, context, name):
        try:
            return super(SearchPage, self).locateConfigurable(context, name)
        except AttributeError:
            if name.startswith('move_'):
                pass
            else:
                raise

        dn = name[len('move_'):]

        session = context.locate(inevow.ISession)
        move = session.getComponent(IMove)
        if move is None:
            raise KeyError, name

        for entry in move:
            if entry.dn == dn:
                return iformless.IConfigurable(MoveItem(entry))

        raise KeyError, name

    def render_move(self, context, data):
        return webform.renderForms('move_%s' % data.dn)[context.tag]

    render_i18n = i18n.render()

def getSearchPage():
    r = SearchPage()
    return r
