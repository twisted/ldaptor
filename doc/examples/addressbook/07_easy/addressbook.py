#!/usr/bin/python
import sys, os
from twisted.internet import app, reactor, defer
from twisted.web import server
from twisted.python import log, formmethod, components
from twisted.web.woven import page, input, controller, model, form, view, interfaces

from ldaptor.protocols.ldap import ldapclient, ldapsyntax, ldapconnector, distinguishedname
from ldaptor import ldapfilter
from ldaptor.protocols import pureldap

class DictionaryModelWithDefaults(model.DictionaryModel):
    def getSubmodel(self, *a, **kw):
        ret = model.DictionaryModel.getSubmodel(self, *a, **kw)
        if ret is None:
            ret = model.adaptToIModel([])
        return ret

components.registerAdapter(DictionaryModelWithDefaults, ldapsyntax.LDAPEntry, interfaces.IModel)
components.registerAdapter(model.ListModel, ldapsyntax.LDAPAttributeSet, interfaces.IModel)

class FormView(view.View):
    def wvupdate_previousSearch(self, request, widget, model):
        name = widget.node.getAttribute('name')
        prevSearch = request.args.get(name, [None])[0]
        if prevSearch:
            widget.setAttribute('value', prevSearch)

class SearchForm(form.FormProcessor):
    isLeaf = 1


    def viewFactory(self, model):
        return FormView(model,
                        templateFile = "searchform.xhtml",
                        templateDirectory = os.path.split(os.path.abspath(__file__))[0])

class Searcher:
    def __init__(self, config):
        self.config = config

    def search(self, **keys):
        filters = []

        while keys:
            k,v = keys.popitem()
            if v:
                try:
                    f = ldapfilter.parseMaybeSubstring(k, v)
                except ldapfilter.InvalidLDAPFilter, e:
                    raise formmethod.InputError, e
                filters.append(f)

        if not filters:
            return {'results': [],
                    'query': None}

        query = pureldap.LDAPFilter_and(
            [pureldap.LDAPFilter_equalityMatch(
            attributeDesc=pureldap.LDAPAttributeDescription('objectClass'),
            assertionValue=pureldap.LDAPAssertionValue('addressbookPerson'))]
            + filters)

        c=ldapconnector.LDAPClientCreator(reactor, ldapclient.LDAPClient)
        d=c.connectAnonymously(self.config['base'], self.config['serviceLocationOverrides'])

        def _search(proto, base, query):
            baseEntry = ldapsyntax.LDAPEntry(client=proto, dn=base)
            d=baseEntry.search(filterObject=query)
            return d

        d.addCallback(_search, self.config['base'], query)
        d.addCallback(lambda results: {'query': query.asText(), 'results': results})
        return d

formSignature = formmethod.MethodSignature(
    formmethod.String("sn", allowNone=0, shortDesc="Last name"),
    formmethod.String("gn", allowNone=0, shortDesc="Given name"),
    formmethod.String("telephoneNumber", allowNone=0, shortDesc="Phone"),
    formmethod.String("description", allowNone=0, shortDesc="Description"),
    )

def main():
    config = {
        'base': distinguishedname.DistinguishedName('ou=People,dc=example,dc=com'),
        'serviceLocationOverrides': {
        distinguishedname.DistinguishedName('dc=example,dc=com'): ('localhost', 10389),
        }
        }

    site = server.Site(SearchForm(formSignature.method(Searcher(config).search)))
    application = app.Application("LDAPressBook")
    application.listenTCP(8088, site)

    log.startLogging(sys.stdout, 0)
    application.run(save=0)

if __name__ == '__main__':
    main()
