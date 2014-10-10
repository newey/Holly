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

from . import Base, Contest, Task
from .smartmappedcollection import smart_mapped_collection

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

    # userset_id = Column(
    #     Integer,
    #     ForeignKey(UserSet.id,
    #                onupdate="CASCADE", ondelete="CASCADE"),
    #                nullable=False,
    #                index=True)
    # userset = relationship(
    #     UserSet,
    #     backref=backref('problemsets',
    #                     collection_class=ordering_list('num'),
    #                     order_by=[num],
    #                     cascade="all, delete-orphan",
    #                     passive_deletes=True))

    # Short name and long human readable title of the problem set.
    name = Column(
        Unicode,
        nullable=False)
    title = Column(
        Unicode,
        nullable=False)

    # We could add the other parameters from Task here and combine
    # the rules here with the rules for each task, but it doesn't
    # seem important...

class ProblemSetItem(Base):
    """ Class to store the membership of a Task or ProblemSet in a ProblemSet

    """
    __tablename__ = 'problemsetitems'
    __table_args__ = (
        UniqueConstraint('problemSet_id', 'task_id'),
        #UniqueConstraint('problemSet_id', 'memberProblemSet_id'),
    )

    # Auto increment primary key.
    id = Column(
        Integer,
        primary_key=True,
        # Needed to enable autoincrement on integer primary keys that
        # are referenced by a foreign key defined on this table.
        autoincrement='ignore_fk')

    # Number of the item for sorting.
    num = Column(
        Integer,
        nullable=False)

    # ProblemSet (id and object) that the item is a member of
    problemSet_id = Column(
        Integer,
        ForeignKey(ProblemSet.id, onupdate="CASCADE", ondelete="CASCADE"),
        nullable=False,
        index=True)
    problemSet = relationship(
        ProblemSet,
        backref=backref(
            'items',
            collection_class=ordering_list('num'),
            order_by=[num],
            cascade="all, delete-orphan",
            passive_deletes=True))

    # Whether the item contains a Task or a ProblemSet
    # isTask = Column(
    #     Boolean,
    #     nullable=False)

    # The Task that is a member of the problem set
    task_id = Column(
        Integer,
        ForeignKey(Task.id, onupdate="CASCADE", ondelete="CASCADE"),
        index=True,
        nullable=False
        )
    task = relationship(
        Task)

    # Alternatively, the ProblemSet that is a member of the ProblemSet
    # memberProblemSet_id = Column(
    #     Integer,
    #     ForeignKey(ProblemSet.id, onupdate="CASCADE", ondelete="CASCADE"),
    #     index=True
    #     )
    # memberProblemSet = relationship(
    #     ProblemSet)