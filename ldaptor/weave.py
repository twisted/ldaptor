from twisted.web.woven import view, model, widgets
from twisted.web.microdom import lmx
from ldaptor.protocols.ldap import ldapsyntax, distinguishedname
from ldaptor.apps.webui import htmlify
from twisted.python import components
from twisted.web.woven import interfaces

view.registerViewForModel(widgets.Text, distinguishedname.DistinguishedName)

class LDAPEntryWidget(widgets.Widget):
    def setUp(self, request, node, data):
        l = lmx(node)
        l.text(htmlify.htmlify_object(data), raw=1)

class DictWidget(widgets.Widget):
    def setUp(self, request, node, data):
        listHeaders = self.getAllPatterns('listHeader', None)
        listFooters = self.getAllPatterns('listFooter', None)
        emptyLists = self.getAllPatterns('emptyList', None)

        if listHeaders:
            for n in listHeaders:
                node.appendChild(n)

        if data:
            for key in data.keys():
                newNode = self.getPattern('keyedListItem')
                widgets.appendModel(newNode, key)
                if not newNode.attributes.get("view"):
                    newNode.attributes["view"] = "DefaultWidget"
                node.appendChild(newNode)
        elif emptyLists:
            for n in emptyLists:
                node.appendChild(n)

        if listFooters:
            for n in listFooters:
                node.appendChild(n)

view.registerViewForModel(LDAPEntryWidget, ldapsyntax.LDAPEntry)

class DictEmulator:
    def __init__(self, entry):
        self.entry = entry
    def keys(self):
        return self.entry.keys()
    def __getitem__(self, key):
        return {'key': key, 'items': list(self.entry[key])}
    def __contains__(self, key):
        return key in self.entry
    def __len__(self):
        return len(self.entry)

components.registerAdapter(model.DictionaryModel, DictEmulator, interfaces.IModel)

class LDAPEntryModel(model.MethodModel):
    def wmfactory_dn(self, request):
        return self.original.dn

    def wmfactory_dict(self, request):
        return DictEmulator(self.original)

    def wmfactory_get(self, request):
        return self.original.get()

    def wmfactory_keys(self, request):
        return self.original.keys()

    def wmfactory_items(self, request):
        return self.original.items()

components.registerAdapter(LDAPEntryModel, ldapsyntax.LDAPEntry, interfaces.IModel)


class SeparatedList(widgets.List):
    def _iterateData(self, parentNode, submodel, data):
        currentListItem = 0
        retVal = []
        for itemNum in range(len(data)):
            # theory: by appending copies of the li node
            # each node will be handled once we exit from
            # here because handleNode will then recurse into
            # the newly appended nodes

            newNode = self.getPattern('listItem')
            if newNode.getAttribute('model') == '.':
                newNode.removeAttribute('model')
            elif not newNode.attributes.get("view"):
                newNode.attributes["view"] = self.defaultItemView
            widgets.appendModel(newNode, itemNum)
            retVal.append(newNode)
            newNode.parentNode = parentNode

            if itemNum < len(data)-1:
                separator = self.getPattern('listSeparator')
                if separator is not None:
                    retVal.append(separator)
                    separator.parentNode = parentNode
        parentNode.childNodes.extend(retVal)
