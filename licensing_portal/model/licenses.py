# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (C) 2012-2016, Ryan P. Wilson
#
#     Authority FX, Inc.
#     www.authorityfx.com

import os, sys

from sqlalchemy import Table, ForeignKey, Column
from sqlalchemy.types import String, Integer, Boolean, DateTime
from sqlalchemy.orm import relationship, backref

from licensing_portal.model import DeclarativeBase, metadata, DBSession
from licensing_portal.model.auth import User

__all__ = ['LicenseType', 'Plugin', 'License', 'Computer', 'Assignment', 'Purchase', 'Settings']


class Settings(DeclarativeBase):

    __tablename__ = "settings"

    id = Column(Integer, autoincrement=True, primary_key=True)
    afx_ip = Column(String)

#One type to many licenses
class LicenseType(DeclarativeBase):

    __tablename__ = "license_type"

    id = Column(Integer, primary_key=True)
    display_name = Column(String, nullable=False)


class Purchase(DeclarativeBase):

    __tablename__ = 'purchase'

    id = Column(Integer, autoincrement=True, primary_key=True)
    transaction_id = Column(String, nullable=False)
    user_id = Column(String, ForeignKey('tg_user.user_id'))
    plugin_id = Column(String, ForeignKey('plugin.id'))
    l_type = Column(Integer, ForeignKey('license_type.id'))
    floating = Column(Boolean, nullable=False)
    count = Column(Integer, nullable=False)
    date = Column(DateTime, nullable=False)

    user = relationship("User")
    plugin = relationship("Plugin")
    license_type = relationship("LicenseType")

class Plugin(DeclarativeBase):

    __tablename__ = 'plugin'

    id = Column(String, primary_key=True)
    display_name = Column(String, nullable=False)

#Many users to many plugins
class License(DeclarativeBase):

    __tablename__ = 'license'

    id = Column(Integer, autoincrement=True, primary_key=True)
    user_id = Column(String, ForeignKey('tg_user.user_id'))
    plugin_id = Column(String, ForeignKey('plugin.id'))
    l_type = Column(Integer, ForeignKey('license_type.id'))
    floating = Column(Boolean, nullable=False)
    count = Column(Integer, nullable=False)
    available = Column(Integer, nullable=False)

    plugin = relationship("Plugin", backref='license')
    user = relationship("User")
    assignment = relationship("Assignment")
    license_type = relationship("LicenseType", backref='license')


#Many computers to one user
class Computer(DeclarativeBase):

    __tablename__ = 'computer'

    id = Column(Integer, autoincrement=True, primary_key=True)
    user_id = Column(String, ForeignKey('tg_user.user_id'))
    display_name = Column(String, nullable=False)
    uuid1 = Column(String, nullable=False)
    uuid2 = Column(String, nullable=False)

    users = relationship("User")
    assignments = relationship("Assignment", backref='computer')


#One assignment to one computers
class Assignment(DeclarativeBase):

    __tablename__ = 'assignment'

    id = Column(Integer, autoincrement=True, primary_key=True)
    user_id = Column(String, ForeignKey('tg_user.user_id'))
    license_id = Column(Integer, ForeignKey('license.id'))
    computer_id = Column(String, ForeignKey('computer.id'))
    count = Column(Integer, nullable=False)
    locked = Column(Boolean, nullable=False)

    users = relationship("User")
    license = relationship("License")

