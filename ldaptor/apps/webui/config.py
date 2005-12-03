from ldaptor import config

def _getSearchFields():
    cfg = config.loadConfig()
    if not cfg.has_section('webui'):
        return
    for raw in cfg.options('webui'):
        if not raw:
            continue
        l=raw.split(None, 2)
        if l[0].lower() == 'search-field':
            pri, name = l[1:]
            pri = int(pri)
            yield (pri, name, raw)

def getSearchFieldByName(name, vars):
    for pri, n, raw in _getSearchFields():
        if n == name:
            cfg = config.loadConfig()
            val = cfg.get('webui', raw, raw=None, vars=vars)
            return val
    return None

def getSearchFieldNames():
    l = list(_getSearchFields())
    l.sort()
    return [name for pri,name,raw in l]
