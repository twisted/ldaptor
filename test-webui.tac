# -*- python -*-
from twisted.application import service, internet
from nevow import appserver, inevow
from ldaptor import config
from ldaptor.apps.webui import main, i18n

application = service.Application("ldaptor-webui")
myService = service.IServiceCollection(application)

cp = config.loadConfig(configFiles=[])
cp.add_section('webui')
cp.set('webui', 'search-field 1 Name',
       '(|(cn=%(input)s)(uid=%(input)s))')
cp.add_section('ldap')
cp.set('ldap', 'base',
       'dc=example,dc=com')

cfg = config.LDAPConfig(serviceLocationOverrides={
    'dc=example,dc=com': ('localhost', 38942),
    })
resource = main.getResource(cfg)

site = appserver.NevowSite(resource)

myServer = internet.TCPServer(38980, site)
myServer.setServiceParent(myService)

############################################################################
import sys, trace
class Coverage(service.Service):
    def startService(self):

        # begin monkey patch --------------------------- 
        def find_executable_linenos(filename):
            """Return dict where keys are line numbers in the line number table."""
            #assert filename.endswith('.py') # YOU BASTARDS
            try:
                prog = open(filename).read()
                prog = '\n'.join(prog.splitlines()) + '\n'
            except IOError, err:
                sys.stderr.write("Not printing coverage data for %r: %s\n" % (filename, err))
                sys.stderr.flush()
                return {}
            code = compile(prog, filename, "exec")
            strs = trace.find_strings(filename)
            return trace.find_lines(code, strs)

        trace.find_executable_linenos = find_executable_linenos
        # end monkey patch ------------------------------

        service.Service.startService(self)
        self.tracer = trace.Trace(count=1, trace=0)
        sys.settrace(self.tracer.globaltrace)

    def stopService(self):
        sys.settrace(None)
        results = self.tracer.results()
        results.write_results(show_missing=1,
                              summary=False,
                              coverdir='coverage')
        service.Service.stopService(self)

svc = Coverage()
svc.setServiceParent(application)
############################################################################
