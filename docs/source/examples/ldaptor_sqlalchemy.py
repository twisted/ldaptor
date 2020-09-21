#! /usr/bin/env python

"""
Example of using LDAPServer with the database.
Employees are stored in the database table and
retrieved on LDAPServerFactory initialization.
LDAP tree can be rebuilt by calling reload_tree method
if the list of users in the database has changed.
SQLAlchemy package is required to run this example.
"""

import sys

from ldaptor.inmemory import ReadOnlyInMemoryLDAPEntry
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols.ldap.ldapserver import LDAPServer

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.python.components import registerAdapter
from twisted.python import log

Base = declarative_base()


class LDAPServerFactory(ServerFactory):
    protocol = LDAPServer

    def __init__(self, db_engine):
        self.db_engine = db_engine
        self.tree = None
        self.reload_tree()

    def reload_tree(self):
        """
        Building LDAP tree.
        Call this method if you need to reload data from the database.
        """
        com_tree = ReadOnlyInMemoryLDAPEntry('dc=com')
        example_tree = com_tree.addChild('dc=example', {})
        users_tree = example_tree.addChild('ou=users', {})

        db_session = Session(self.db_engine)

        for employee in db_session.query(Employee):
            users_tree.addChild('uid={}'.format(employee.uid), {
                'uid': [employee.uid],
                'givenName': [employee.first_name],
                'sn': [employee.last_name],
                'email': [employee.email],
            })

        db_session.close()

        self.tree = com_tree


class Employee(Base):
    __tablename__ = 'employee'

    id = Column(Integer, primary_key=True)
    uid = Column(String(255), nullable=False)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)


def create_db():
    """Creating a database with a table of employees and a couple of rows"""
    db_engine = create_engine('sqlite://')
    Base.metadata.bind = db_engine
    Employee.__table__.create()

    db_session = Session(db_engine)

    employee1 = Employee()
    employee1.uid = 'f.example'
    employee1.first_name = 'First'
    employee1.last_name = 'Example'
    employee1.email = 'first@example.com'
    db_session.add(employee1)

    employee2 = Employee()
    employee2.uid = 's.example'
    employee2.first_name = 'Second'
    employee2.last_name = 'Example'
    employee2.email = 'second@example.com'
    db_session.add(employee2)

    db_session.commit()
    db_session.close()

    return db_engine


if __name__ == '__main__':
    engine = create_db()

    log.startLogging(sys.stderr)

    registerAdapter(lambda x: x.tree, LDAPServerFactory, IConnectedLDAPEntry)
    factory = LDAPServerFactory(engine)
    reactor.listenTCP(8080, factory)
    reactor.run()
