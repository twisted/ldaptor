import errno
from nevow import inevow, flat, compy, context

### from nevow.inevow
class II18NConfig(compy.Interface):
    """
    Interface for I18N configuration.

    @ivar domain: the gettext domain

    @type domain: str

    @ivar localeDir: path to the messages files or None to use the
    system default

    @type localeDir: str or None
    """
    domain = None
    localeDir = None

        
class ILanguages(compy.Interface):
    """
    Marker interface for the sequence of strings that defines the
    languages requested by the user.
    """
    
### from nevow.i18n
def languagesFactory(ctx):
    header = inevow.IRequest(ctx).getHeader('accept-language')
    if header is None:
        return []
    langs = []
    for lang in header.split(','):
        quality = 1.0
        if ';' in lang:
            lang, quality = lang.split(';', 1)
            if quality[:2] == 'q=':
                try:
                    quality = float(quality[2:])
                except ValueError:
                    pass
        langs.append((quality, lang))
        if '-' in lang:
            langs.append((quality, lang.split('-')[0])) 
    langs.sort(lambda a,b: cmp(b[0], a[0]))
    return [lang for quality, lang in langs]

    
class I18NConfig(object):
    __implements__ = II18NConfig,

    def __init__(self,
                 domain=None,
                 localeDir=None,
                 ):
        self.domain = domain
        self.localeDir = localeDir

        
class PlaceHolder(object):
    def __init__(self, translator, original, _mod=None, **kw):
        self.translator = translator
        self.original = original
        self.kw = kw
        if _mod is None:
            _mod = []
        self.mod = _mod

    def __mod__(self, other):
        return self.__class__(self.translator,
                              self.original,
                              _mod=self.mod+[other])

    def __repr__(self):
        args = [
            'translator=%r' % self.translator,
            'original=%r' % self.original,
            ]
        if self.kw:
            args.append('**%r' % self.kw)
        s = '%s(%s)' % (
            self.__class__.__name__,
            ', '.join(args),
            )
        for mod in self.mod:
            s += ' %% %r' % (mod,)
        return s

class FlatteningProxy(object):
    def __init__(self, ctx, original):
        self.ctx = ctx
        self.original = original
    def __getitem__(self, key):
        return flat.flatten(self.original[key], self.ctx)
    def __str__(self):
        return str(self.original)
    def __repr__(self):
        return repr(self.original)
    def __int__(self):
        return int(self.original)
    def __float__(self):
        return float(self.original)

def flattenL10n(placeHolder, ctx):
    kw = placeHolder.kw

    try:
        languages = ILanguages(ctx)
    except compy.CannotAdapt:
        pass
    else:
        kw = dict(kw) # copy before we mutate it
##         kw['languages'] = languages
        kw.setdefault('languages', languages) #TODO

    try:
        cfg = II18NConfig(ctx)
    except compy.CannotAdapt:
        pass
    else:
        kw = dict(kw) # copy before we mutate it
        if cfg.domain is not None:
            kw['domain'] = cfg.domain
        if cfg.localeDir is not None:
            kw['localeDir'] = cfg.localeDir

    s = placeHolder.translator(placeHolder.original, **kw)
    for mod in placeHolder.mod:
        if isinstance(mod, tuple):
            l = tuple([FlatteningProxy(ctx, x) for x in mod])
        else:
            l = FlatteningProxy(ctx, mod)
        s = s % l
    return s

    
class Translator(object):
    """
    A gettext-like Translator for Nevow.

    The major difference between this and naive gettext is that with
    Translator, the actual translation is done as part of Nevow's
    flattening process, allowing per-user settings to be retrieved via
    the context.

    @ivar translator: The actual translation function to use.

    @ivar args: keyword arguments to pass to translator.
    """
    translator = None
    args = None

    def _gettextTranslation(self, s,
                            domain=None,
                            localeDir=None,
                            languages=None):
        import gettext
        try:
            translation = gettext.translation(
                domain=domain,
                localedir=localeDir,
                languages=languages,
                )
        except IOError:
            translation = gettext.NullTranslations()
        return translation.ugettext(s)             

    def __init__(self, **kw):
        """
        Initialize.

        @keyword translator: The translator function to use.

        @param kw: keyword arguments for the translator function.
        """
        translator = kw.pop('translator', None)
        if translator is not None:
            self.translator = translator
        if self.translator is None:
            self.translator = self._gettextTranslation
        self.args = kw

    def __call__(self, original, **kw):
        """
        Translate a string.

        @param original: string to translate

        @type original: basestr

        @param kw: keyword arguments for the translator.
        Arguments given here will override the ones given
        at initialization.

        @return: a placeholder that will be translated
        when flattened.

        @rtype: PlaceHolder
        """
        args = dict(self.args)
        args.update(kw)
        return PlaceHolder(self.translator, original, **args)

        
_ = Translator()


def render(translator=None):
    """
    Render a localised message.

    >>> from nevow import i18n, rend
    >>> class MyPage(rend.Page):
    ...     render_i18n = i18n.render()

    or, to use a specific domain:

    >>> from nevow import i18n, rend
    >>> _ = i18n.Translator(domain='foo')
    >>> class MyPage(rend.Page):
    ...     render_i18n = i18n.render(translator=_)

    """
    if translator is None:
        translator = _

    def _render(page, ctx, data):
        # TODO why does this get page? Is it
        # the Page's self? Why would this look
        # like a bound method?
        children = ctx.tag.children
        ctx.tag.clear()
        for child in children:
            if isinstance(child, basestring):
                child = translator(child)
            ctx.tag[child]
        return ctx.tag

    return _render

# TODO also provide macro()

### from nevow.__init__
compy.registerAdapter(languagesFactory,
                      context.RequestContext,
                      ILanguages)

flat.registerFlattener(flattenL10n, PlaceHolder)
                       
