from twisted.python.usage import UsageError
from twisted.python import usage, reflect
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import distinguishedname

class Options(usage.Options):
    optParameters = ()
    def postOptions(self):
	postOpt = {}
	reflect.addMethodNamesToDict(self.__class__, postOpt, "postOptions_")
	for name in postOpt.keys():
	    method = getattr(self, 'postOptions_'+name)
	    method()

class Options_service_location(Options):
    def opt_service_location(self, value):
	"""Service location, in the form BASEDN:HOST[:PORT]"""

	if not self.opts.has_key('service-location'):
	    self.opts['service-location']={}

	base, location = value.split(':', 1)

	if not location:
	    raise usage.UsageError, "service-location must specify host"

	if ':' in location:
	    host, port = location.split(':', 1)
	else:
	    host, port = location, None

	if not host:
	    host = None

	if not port:
	    port = None

	dn = distinguishedname.DistinguishedName(base)
	self.opts['service-location'][dn] = (host, port)

    def postOptions_service_location(self):
	if not self.opts.has_key('service-location'):
	    self.opts['service-location']={}

class Options_base(Options):
    optParameters = (
	('base', None, None,
	 "LDAP base dn"),
	)

    def postOptions_base(self):
	# check that some things are given
	if self.opts['base'] is None:
	    raise usage.UsageError, "%s must be given" % 'base'

class Options_scope(Options):
    optParameters = (
	('scope', None, 'sub',
	 "LDAP search scope (one of base, one, sub)"),
	)

    def postOptions_scope(self):
	synonyms = {
	    'base': 'baseObject',
	    'single': 'singleLevel',
	    'subtree': 'wholeSubtree',
	    'sub': 'wholeSubtree',
	    }
	scope = self.opts['scope']
	scope=synonyms.get(scope, scope)
	try:
	    scope=getattr(pureldap, 'LDAP_SCOPE_'+scope)
	except AttributeError:
	    raise usage.UsageError, "bad scope: %s" % scope
	self.opts['scope'] = scope

class Options_bind(Options):
    optParameters = (
	('binddn', None, None,
	 "use Distinguished Name to bind to the directory"),
	('bind-auth-fd', None, None,
	 "read bind password from filedescriptor"),
	)

    def postOptions_bind_auth_fd_numeric(self):
	val=self.opts['bind-auth-fd']
	if val is not None:
	    try:
		val = int(val)
	    except ValueError:
		raise usage.UsageError, "%s value must be numeric" % 'bind-auth-fd'
	    self.opts['bind-auth-fd'] = val

class Options_bind_mandatory(Options_bind):
    def postOptions_bind_mandatory(self):
	if not self.opts['binddn']:
	    raise usage.UsageError, "%s must be given" % 'binddn'
