import os.path
import ConfigParser
from zope.interface import implements
from ldaptor import interfaces
from ldaptor.insensitive import InsensitiveString
from ldaptor.protocols.ldap import distinguishedname

class MissingBaseDNError(Exception):
    """Configuration must specify a base DN"""

    def __str__(self):
        return self.__doc__

class LDAPConfig(object):
    implements(interfaces.ILDAPConfig)

    baseDN = None
    identityBaseDN = None
    identitySearch = None

    def __init__(self,
                 baseDN=None,
                 serviceLocationOverrides=None,
                 identityBaseDN=None,
                 identitySearch=None):
        if baseDN is not None:
            baseDN = distinguishedname.DistinguishedName(baseDN)
            self.baseDN = baseDN
        self.serviceLocationOverrides = {}
        if serviceLocationOverrides is not None:
            for k,v in serviceLocationOverrides.items():
                dn = distinguishedname.DistinguishedName(k)
                self.serviceLocationOverrides[dn]=v
        if identityBaseDN is not None:
            identityBaseDN = distinguishedname.DistinguishedName(identityBaseDN)
            self.identityBaseDN = identityBaseDN
        if identitySearch is not None:
            self.identitySearch = identitySearch

    def getBaseDN(self):
        if self.baseDN is not None:
            return self.baseDN

        cfg = loadConfig()
        try:
            return cfg.get('ldap', 'base')
        except (ConfigParser.NoOptionError,
                ConfigParser.NoSectionError):
            raise MissingBaseDNError

    def getServiceLocationOverrides(self):
        r = self._loadServiceLocationOverrides()
        r.update(self.serviceLocationOverrides)
        return r

    def _loadServiceLocationOverrides(self):
        serviceLocationOverride = {}
        cfg = loadConfig()
        for section in cfg.sections():
            if section.lower().startswith('service-location '):
                base = section[len('service-location '):].strip()

                host = None
                if cfg.has_option(section, 'host'):
                    host = cfg.get(section, 'host')
                    if not host:
                        host = None

                port = None
                if cfg.has_option(section, 'port'):
                    port = cfg.get(section, 'port')
                    if not port:
                        port = None

                dn = distinguishedname.DistinguishedName(stringValue=base)
                serviceLocationOverride[dn]=(host, port)
        return serviceLocationOverride

    def copy(self, **kw):
        if 'baseDN' not in kw:
            kw['baseDN'] = self.baseDN
        if 'serviceLocationOverrides' not in kw:
            kw['serviceLocationOverrides'] = self.serviceLocationOverrides
        if 'identityBaseDN' not in kw:
            kw['identityBaseDN'] = self.identityBaseDN
        if 'identitySearch' not in kw:
            kw['identitySearch'] = self.identitySearch
        r = self.__class__(**kw)
        return r

    def getIdentityBaseDN(self):
        if self.identityBaseDN is not None:
            return self.identityBaseDN

        cfg = loadConfig()
        try:
            return cfg.get('authentication', 'identity-base')
        except (ConfigParser.NoOptionError,
                ConfigParser.NoSectionError):
            return self.getBaseDN()

    def getIdentitySearch(self, name):
        data = {
            'name': name,
            }

        if self.identitySearch is not None:
            f = self.identitySearch % data
        else:
            cfg = loadConfig()
            try:
                f=cfg.get('authentication', 'identity-search', vars=data)
            except (ConfigParser.NoOptionError,
                    ConfigParser.NoSectionError):
                f='(|(cn=%(name)s)(uid=%(name)s))' % data
        return f


DEFAULTS = {
    'samba': { 'use-lmhash': 'no',
               },
    }

CONFIG_FILES = [
    '/etc/ldaptor/global.cfg',
    os.path.expanduser('~/.ldaptor/global.cfg'),
    ]

__config = None

def loadConfig(configFiles=None,
               reload=False):
    """
    Load configuration file.
    """
    global __config
    if __config is None or reload:
        x = ConfigParser.SafeConfigParser()
        x.optionxform = InsensitiveString

        for section, options in DEFAULTS.items():
            x.add_section(section)
            for option, value in options.items():
                x.set(section, option, value)

        if configFiles is None:
            configFiles = CONFIG_FILES
        x.read(configFiles)
        __config = x
    return __config

def useLMhash():
    """
    Read configuration file if necessary and return whether
    to use LanMan hashes or not.
    """
    cfg = loadConfig()
    return cfg.getboolean('samba', 'use-lmhash')
