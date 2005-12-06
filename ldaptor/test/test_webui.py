from twisted.trial import unittest

import urllib, string

from twisted.internet import address, protocol
from twisted.python import components
from twisted.web import microdom

from nevow import appserver

from ldaptor import inmemory, interfaces, config
from ldaptor.protocols.ldap import ldapserver
from ldaptor.apps.webui import main

from ldaptor.test import mockweb, util

def getTextContents(node):
    s=u''
    for text in node.childNodes:
        assert (isinstance(text, microdom.Text)
                or isinstance(text, microdom.EntityReference))
        if isinstance(text, microdom.Text):
            s += text.toxml()
        elif isinstance(text, microdom.EntityReference):
            if text.eref.startswith('#x'):
                n = int(text.eref[len('#x'):], 16)
                s += unichr(n)
            else:
                s += text.toxml()
        else:
            raise RuntimeError, 'TODO'
    return s

class MockLDAPConfig(config.LDAPConfig):
    def _loadServiceLocationOverrides(self):
        return {}

class SiteMixin:
    def setUp(self):
        db = inmemory.ReadOnlyInMemoryLDAPEntry('')
        db.addChild('cn=schema',
                    {'objectClass': ['TODO'],
                     'cn': ['schema'],
                     'attributeTypes': [
            """( 0.9.2342.19200300.100.1.25
            NAME ( 'dc' 'domainComponent' )
            DESC 'RFC1274/2247: domain component'
            EQUALITY caseIgnoreIA5Match
            SUBSTR caseIgnoreIA5SubstringsMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )""",
            """( 2.5.4.0 NAME 'objectClass'
            DESC 'RFC2256: object classes of the entity'
            EQUALITY objectIdentifierMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )""",
            """( 2.5.4.4 NAME ( 'sn' 'surname' )
            DESC 'RFC2256: last (family) name(s) for which the entity is known by'
            SUP name )""",
            """( 2.5.4.3 NAME ( 'cn' 'commonName' )
            DESC 'RFC2256: common name(s) for which the entity is known by'
            SUP name )""",
            """( 2.5.4.35 NAME 'userPassword'
            DESC 'RFC2256/2307: password of user'
            EQUALITY octetStringMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )""",
            """( 2.5.4.20 NAME 'telephoneNumber'
            DESC 'RFC2256: Telephone Number'
            EQUALITY telephoneNumberMatch
            SUBSTR telephoneNumberSubstringsMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.50{32} )""",
            """( 2.5.4.34 NAME 'seeAlso'
            DESC 'RFC2256: DN of related object'
            SUP distinguishedName )""",
            """( 2.5.4.13 NAME 'description'
            DESC 'RFC2256: descriptive information'
            EQUALITY caseIgnoreMatch
            SUBSTR caseIgnoreSubstringsMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )""",
            ],
                     'objectClasses': [
            """( 2.5.6.0 NAME 'top'
            DESC 'top of the superclass chain'
            ABSTRACT
            MUST objectClass )""",
            """( 1.3.6.1.4.1.1466.344 NAME 'dcObject'
            DESC 'RFC2247: domain component object'
            SUP top AUXILIARY MUST dc )""",
            """( 2.5.6.6 NAME 'person'
            DESC 'RFC2256: a person'
            SUP top
            STRUCTURAL
            MUST ( sn $ cn )
            MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )""",
            ],
                     })
        self.com = db.addChild('dc=com', {})
        self.example = self.com.addChild('dc=example',
                                         {'objectClass': ['dcObject'],
                                          'dc': ['example'],
                                          'subschemaSubentry': ['cn=schema'],
                                          })
        self.foo = self.example.addChild('uid=foo',
                                         {'objectClass': ['person'],
                                          'uid': ['foo'],
                                          'cn': ['Foo Bar'],
                                          'sn': ['Bar'],
                                          'userPassword': ['{SSHA}1feEJLgP7OB5mUKU/fYJzBoAGlOrze8='], # "foo"
                                          'subschemaSubentry': ['cn=schema'],
                                          })

        class LDAPServerFactory(protocol.ServerFactory):
            protocol = ldapserver.LDAPServer
            def __init__(self, root):
                self.root = root

        components.registerAdapter(lambda x: x.root,
                                   LDAPServerFactory,
                                   interfaces.IConnectedLDAPEntry)
        serverFactory = LDAPServerFactory(db)

        def _doConnect(factory):
            factory.doStart()
            client = factory.buildProtocol(address.IPv4Address('TCP', 'localhost', '389'))
            server = serverFactory.buildProtocol(address.IPv4Address('TCP', 'localhost', '1024'))
            util.returnConnected(server, client)

        cfg = MockLDAPConfig(baseDN='dc=example,dc=com',
                             serviceLocationOverrides={'': _doConnect},
                             identityBaseDN='dc=example,dc=com',)
        root = main.getResource(cfg)
        self.site = appserver.NevowSite(root)
        self.site.startFactory()

    def tearDown(self):
        for name, sess in self.site.resource.sessions.items():
            sess.expire()
        self.site.stopFactory()

    def getPage(self, url, cookies, *a, **kw):
        if cookies:
            getter = mockweb.getPage
        else:
            getter = mockweb.getPage_noCookies
        kw['extraInfo'] = True
        d = getter(self.site, url, *a, **kw)
        data = util.pumpingDeferredResult(d)

        tree = microdom.parseString(data['page'], beExtremelyLenient=True)
        assert 'tree' not in data
        data['tree'] = tree

        title = data['tree'].getElementsByTagName('title')[0]
        assert 'title' not in data
        data['title'] = getTextContents(title)

        return data


class TestCSS(SiteMixin, unittest.TestCase):
    urls = [
        'http://localhost/',
        'http://localhost/dc=example,dc=com/',
        'http://localhost/dc=example,dc=com/search',
        'http://localhost/dc=example,dc=com/search/',
        'http://localhost/dc=example,dc=com/edit/', # to test login
        ]

    def _checkResults(self, data, cookies):
        head = data['tree'].getElementsByTagName('head')
        assert len(head) == 1, \
               "Expected exactly one <head> element, got %r" % head
        links = head[0].getElementsByTagName('link')
        for link in links:
            if link.getAttribute('rel') == 'stylesheet':
                href = link.getAttribute('href')
                u = data['url'].clear().click(href)
                self.assertEquals(u.scheme, 'http')
                self.assertEquals(u.netloc, 'localhost')
                self.assertEquals(u.queryList(), [])
                l = u.pathList()
                if cookies:
                    self.assertEquals(len(l), 1, "pathList %r for %s should be one element long" % (l, data['url']))
                else:
                    self.assertEquals(len(l), 2, "pathList %r for %s should be two elements long" % (l, data['url']))
                    self.failUnless(l[0].startswith('__session_key__'))
                    l.pop(0)
                self.failUnless(l[0].endswith('.css'), "url %s has invalid CSS reference %r" % (data['url'], l[0]))
                basename = l[0][:-len('.css')]
                self.failUnless(len(basename) >= 1)
                for c in basename:
                    self.failUnless(c in string.ascii_lowercase, "url %s has invalid character %r in CSS reference %r" % (data['url'], c, l[0]))

    def checkPage(self, url, cookies):
        data = self.getPage(url, cookies)
        self._checkResults(data, cookies)

    def test_form_css(self):
        for u in self.urls:
            self.checkPage(u, cookies=True)

    def test_form_css_noCookies(self):
        for u in self.urls:
            self.checkPage(u, cookies=False)


class TestAuthenticatedCSS(TestCSS):
    urls = [
        'http://localhost/dc=example,dc=com/edit',
        'http://localhost/dc=example,dc=com/edit/',
        'http://localhost/dc=example,dc=com/edit/uid=foo,dc=example,dc=com',
        'http://localhost/dc=example,dc=com/add',
        'http://localhost/dc=example,dc=com/add/',
        'http://localhost/dc=example,dc=com/add/manual/dcObject',
        'http://localhost/dc=example,dc=com/change_password',
        'http://localhost/dc=example,dc=com/change_password/',
        'http://localhost/dc=example,dc=com/change_password/uid=foo,dc=example,dc=com',
        'http://localhost/dc=example,dc=com/mass_change_password',
        'http://localhost/dc=example,dc=com/mass_change_password/',
        'http://localhost/dc=example,dc=com/mass_change_password/(uid=foo)',
        'http://localhost/dc=example,dc=com/delete',
        'http://localhost/dc=example,dc=com/delete/',
        'http://localhost/dc=example,dc=com/delete/uid=foo,dc=example,dc=com',
        'http://localhost/dc=example,dc=com/move',
        'http://localhost/dc=example,dc=com/move/',
        'http://localhost/dc=example,dc=com/move/uid=foo,dc=example,dc=com',
        ]

    def checkPage(self, url, cookies):
        data = self.getPage(url, cookies)
        self.assertEquals(data['title'], 'Login')

        # fill form, submit
        forms = data['tree'].getElementsByTagName('form')
        self.assertEquals(len(forms), 1)
        form = forms[0]
        self.assertEquals(form.getAttribute('enctype', 'application/x-www-form-urlencoded'),
                          'application/x-www-form-urlencoded')
        data = self.getPage(data['url'].clear().click(form.getAttribute('action')),
                            cookies,
                            method=form.getAttribute('method', 'get').upper(),
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            postdata='&'.join(['%s=%s' % (urllib.quote('username'),
                                                           urllib.quote('foo')),
                                               '%s=%s' % (urllib.quote('password'),
                                                          urllib.quote('foo')),
                                               ]),
                            )
        self._checkResults(data, cookies)

class TestAuthentication(SiteMixin, unittest.TestCase):
    def test_ensureBind(self):
        self.failUnless(self.foo.bind('foo'))

    def checkPage(self, url, cookies):
        data = self.getPage(url, cookies)
        self.assertEquals(data['title'], 'Login')

        # fill form, submit
        forms = data['tree'].getElementsByTagName('form')
        self.assertEquals(len(forms), 1)
        form = forms[0]
        self.assertEquals(form.getAttribute('enctype', 'application/x-www-form-urlencoded'),
                          'application/x-www-form-urlencoded')
        data = self.getPage(data['url'].clear().click(form.getAttribute('action')),
                            cookies,
                            method=form.getAttribute('method', 'get').upper(),
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            postdata='&'.join(['%s=%s' % (urllib.quote('username'),
                                                           urllib.quote('foo')),
                                               '%s=%s' % (urllib.quote('password'),
                                                          urllib.quote('foo')),
                                               ]),
                            )

        return data

    def test_edit(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/edit/dc=example,dc=com', cookies=True)
        self.assertEquals(data['title'], u'Ldaptor Edit Page')

    def test_edit_noCookies(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/edit/dc=example,dc=com', cookies=False)
        self.assertEquals(data['title'], u'Ldaptor Edit Page')

    def test_move(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/move', cookies=True)
        self.assertEquals(data['title'], u'Ldaptor Move Page')

    def test_move_noCookies(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/move', cookies=False)
        self.assertEquals(data['title'], u'Ldaptor Move Page')

    def test_add(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/add', cookies=True)
        self.assertEquals(data['title'], u'Ldaptor Add Page')

    def test_add_noCookies(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/add', cookies=False)
        self.assertEquals(data['title'], u'Ldaptor Add Page')

    def test_delete(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/delete/dc=example,dc=com', cookies=True)
        self.assertEquals(data['title'], u'Ldaptor Delete Page')

    def test_delete_noCookies(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/delete/dc=example,dc=com', cookies=False)
        self.assertEquals(data['title'], u'Ldaptor Delete Page')

    def test_mass_change_password(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/mass_change_password', cookies=True)
        self.assertEquals(data['title'], u'Ldaptor Mass Password Change Page')

    def test_mass_change_password_noCookies(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/mass_change_password', cookies=False)
        self.assertEquals(data['title'], u'Ldaptor Mass Password Change Page')

    def test_change_password(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/change_password', cookies=True)
        self.assertEquals(data['title'], u'Ldaptor Password Change Page')

    def test_change_password_noCookies(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/change_password', cookies=False)
        self.assertEquals(data['title'], u'Ldaptor Password Change Page')

class TestDelete(SiteMixin, unittest.TestCase):
    def checkPage(self, url, cookies):
        data = self.getPage(url, cookies)
        self.assertEquals(data['title'], 'Login')

        # fill form, submit
        forms = data['tree'].getElementsByTagName('form')
        self.assertEquals(len(forms), 1)
        form = forms[0]
        self.assertEquals(form.getAttribute('enctype', 'application/x-www-form-urlencoded'),
                          'application/x-www-form-urlencoded')
        data = self.getPage(data['url'].clear().click(form.getAttribute('action')),
                            cookies,
                            method=form.getAttribute('method', 'get').upper(),
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            postdata='&'.join(['%s=%s' % (urllib.quote('username'),
                                                          urllib.quote('foo')),
                                               '%s=%s' % (urllib.quote('password'),
                                                          urllib.quote('foo')),
                                               ]),
                            )
        return data

    def test_nonExisting(self):
        data = self.checkPage('http://localhost/dc=example,dc=com/delete/uid=bar,dc=example,dc=com', cookies=True)
        self.assertEquals(data['title'], u'Ldaptor Delete Page')
        self.failUnless('An error occurred' in data['page'])
        self.failUnless('noSuchObject' in data['page'])

    def test_existing(self):
        # TODO cookies don't work because there's nothing that would carry over their state
        data = self.checkPage('http://localhost/dc=example,dc=com/delete/uid=foo,dc=example,dc=com', cookies=False)
        self.assertEquals(data['title'], u'Ldaptor Delete Page')
        self.failUnless('<p>Remove <span>uid=foo,dc=example,dc=com</span>?</p>' in data['page'])

        # fill form, submit
        forms = data['tree'].getElementsByTagName('form')
        self.assertEquals(len(forms), 1)
        form = forms[0]
        # TODO support multipart/form-data, that's what the form tells us to use
##         self.assertEquals(form.getAttribute('enctype', 'application/x-www-form-urlencoded'),
##                           'application/x-www-form-urlencoded')
        action = data['url'].clear().click(form.getAttribute('action'))
        data = self.getPage(action,
                            cookies=False,
                            method=form.getAttribute('method', 'get').upper(),
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            )

        self.assertEquals(data['title'], 'Ldaptor Search Page')
        self.failUnless('Success' in data['page'])

        d = self.example.children()
        children = util.pumpingDeferredResult(d)
        self.assertEquals(children, [])
