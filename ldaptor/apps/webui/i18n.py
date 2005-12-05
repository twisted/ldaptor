from nevow.inevow import ILanguages
from nevow.i18n import I18NConfig
from nevow import i18n

_ = i18n.Translator(domain='ldaptor-webui')

def render():
    return i18n.render(translator=_)
