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

from . import Base, Contest, Task, User, UserSet
from .smartmappedcollection import smart_mapped_collection

accessible_problemsets = Table(
    'accessible_problemsets',
    Base.metadata,
    Column('userset_id', Integer, ForeignKey('usersets.id')),
    Column('problemset_id', Integer, ForeignKey('problemsets.id')))

pinned_problemsets = Table(
    'pinned_problemsets',
    Base.metadata,
    Column('problemset_id', Integer, ForeignKey('problemsets.id')),
    Column('user_id', Integer, ForeignKey('users.id')))

problemsets_contents = Table(
    'problemsets_contents',
    Base.metadata,
    Column('problemset_id', Integer, ForeignKey('problemsets.id')),
    Column('task_id', Integer, ForeignKey('tasks.id')))

class ProblemSet(Base):
    """ Class to store a problem set for training purposes

    """
    __tablename__ = 'problemsets'
    __table_args__ = (
        UniqueConstraint('contest_id', 'num'),
        UniqueConstraint('contest_id', 'name'),
    )

    # Auto increment primary key.
    id = Column(
        Integer,
        primary_key=True,
        # Needed to enable autoincrement on integer primary keys that
        # are referenced by a foreign key defined on this table.
        autoincrement='ignore_fk')

    # Number of the problem set for sorting.
    num = Column(
        Integer,
        nullable=False)

    # Contest (id and object) owning the problem set.
    contest_id = Column(
        Integer,
        ForeignKey(Contest.id,
                   onupdate="CASCADE", ondelete="CASCADE"),
                   nullable=False,
                   index=True)
    contest = relationship(
        Contest,
        backref=backref('problemsets',
                        collection_class=ordering_list('num'),
                        order_by=[num],
                        cascade="all, delete-orphan",
                        passive_deletes=True))

    # Short name and long human readable title of the problem set.
    name = Column(
        Unicode,
        nullable=False)
    title = Column(
        Unicode,
        nullable=False)

    # The user sets who have access to this problem set
    userSets = relationship("UserSet",
        secondary=accessible_problemsets,
        backref="problemSets")

    # The users who havve pinned this problem set
    usersWhoPinned = relationship("User",
        secondary=pinned_problemsets,
        backref="pinnedSets")

    # The tasks that are members of this problem set
    tasks = relationship("Task",
        secondary=problemsets_contents,
        backref="problemSets")

    def numProblems(self):
        return len(self.items)

    def isPinned(self, user):
        return user in self.usersWhoPinned
