#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Contest Management System - http://cms-dev.github.io/
# Copyright © 2010-2014 Giovanni Mascellani <mascellani@poisson.phc.unipi.it>
# Copyright © 2010-2012 Stefano Maggiolo <s.maggiolo@gmail.com>
# Copyright © 2010-2012 Matteo Boscariol <boscarim@hotmail.com>
# Copyright © 2012-2014 Luca Wehrstedt <luca.wehrstedt@gmail.com>
# Copyright © 2013 Bernard Blackham <bernard@largestprime.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Task-related database interface for SQLAlchemy.

"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

from datetime import timedelta

from sqlalchemy.schema import Column, ForeignKey, CheckConstraint, \
    UniqueConstraint, ForeignKeyConstraint, Table
from sqlalchemy.types import Boolean, Integer, Float, String, Unicode, \
    Interval, Enum
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.orderinglist import ordering_list

from . import Base, Contest, User
from .smartmappedcollection import smart_mapped_collection

users_to_usersets = Table(
    'users_to_usersets',
    Base.metadata,
    Column('userset_id',
           Integer,
           ForeignKey('usersets.id', onupdate="CASCADE", ondelete="CASCADE")
           ),
    Column('user_id',
           Integer,
           ForeignKey('users.id', onupdate="CASCADE", ondelete="CASCADE")
           )
    )
                          

class UserSet(Base):
    """ Class to store a user set for training purposes

    """
    __tablename__ = 'usersets'
    __table_args__ = (
        UniqueConstraint('id', 'name'),
        )

    # Auto increment primary key.
    id = Column(
        Integer,
        primary_key=True,
        # Needed to enable autoincrement on integer primary keys that
        # are referenced by a foreign key defined on this table.
        autoincrement='ignore_fk')

    # Short name and long human readable title of the user set.
    name = Column(
        Unicode,
        nullable=False)
    title = Column(
        Unicode,
        nullable=False)

    # The type of userset:
    #  0: normal userSet editable by administrators
    #  1: Special non-editable set for an individual user
    #  2: Special non-editable set for all users
    setType = Column(
        Integer,
        nullable=False,
        default=0,
        index=True)

    users = relationship("User",
        secondary=users_to_usersets,
        backref="userSets")

    # We could add the other parameters from Task here and combine
    # the rules here with the rules for each task, but it doesn't
    # seem important...
