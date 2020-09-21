COUNTRY = (
    'dc=fr',
    {
        'objectClass': ['dcObject','country'],
        'dc': ['fr'],
        'description': ["French country 2 letters iso description"],
    }
)
COMPANY = (
    'dc=example',
    {
        'objectClass': ['dcObject','organization'],
        'dc': ['example'],
        'description': ["My organisation"],
        'o': ["Example, Inc"],
    }
)
PEOPLE = (
    'ou=people',
    {
        'ou': ['people'],
        'description': ['People from Example Inc'],
        'objectclass': ['organizationalunit'],
    }
)
USERS = [
        (
            'uid=yoen',
            {
                'objectClass': ['people', 'inetOrgPerson'],
                'cn': ['Yoen Van der Weld'],
                'sn': ['Van der Weld'],
                'givenName': ['Yoen'],
                'uid': ['yoen'],
                'mail': ['/home/yoen/mailDir'],
                'userPassword': ['secret']
            }
        ),
        (
            'uid=esteban',
            {
                'objectClass': ['people', 'inetOrgPerson'],
                'cn': ['Esteban Garcia Marquez'],
                'sn': ['Garcia Marquez'],
                'givenName': ['Esteban'],
                'uid': ['esteban'],
                'mail': ['/home/esteban/mailDir'],
                'userPassword': ['secret2']
            }
        ),
        (
            'uid=mohamed',
            {
                'objectClass': ['people', 'inetOrgPerson'],
                'cn': ['Mohamed Al Ghâlib'],
                'sn': ['Al Ghâlib'],
                'givenName': ['mohamed'],
                'uid': ['mohamed'],
                'mail': ['/home/mohamed/mailDir'],
                'userPassword': ['secret3']
            }
        ),
    ]
