from nevow_i18n import I18NConfig, ILanguages
import nevow_i18n

_ = nevow_i18n.Translator(domain='ldaptor-webui')

def render():
    return nevow_i18n.render(translator=_)
