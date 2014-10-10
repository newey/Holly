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
    UniqueConstraint, ForeignKeyConstraint
from sqlalchemy.types import Boolean, Integer, Float, String, Unicode, \
    Interval, Enum
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.orderinglist import ordering_list

from . import Base, UserSet, User
from .smartmappedcollection import smart_mapped_collection

class UserSetItem(Base):
    """ Class to store the membership of a User in a UserSet

    """
    __tablename__ = 'usersetitem'

    # Auto increment primary key.
    id = Column(
        Integer,
        primary_key=True,
        # Needed to enable autoincrement on integer primary keys that
        # are referenced by a foreign key defined on this table.
        autoincrement='ignore_fk')

    # UserSet (id and object) that the item is a member of
    userSet_id = Column(
        Integer,
        ForeignKey(UserSet.id, onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
        index=True)
    userSet = relationship(
        UserSet,
        backref=backref(
            'items',
            cascade="all, delete-orphan",
            passive_deletes=True)
        )

    # The User has all memberships to usersets
    user_id = Column(
        Integer,
        ForeignKey(User.id, onupdate="CASCADE", ondelete="CASCADE"),
        index=True,
        nullable=False
        )
    user = relationship(
        User,
        backref=backref(
            'memberships',
            cascade="all, delete-orphan",
            passive_deletes=True)
        )