# -*- coding: utf-8 -*-

# Contest Management System - http://cms-dev.github.io/
# Copyright © 2010-2013 Giovanni Mascellani <mascellani@poisson.phc.unipi.it>
# Copyright © 2010-2014 Stefano Maggiolo <s.maggiolo@gmail.com>
# Copyright © 2010-2012 Matteo Boscariol <boscarim@hotmail.com>
# Copyright © 2012-2014 Luca Wehrstedt <luca.wehrstedt@gmail.com>
# Copyright © 2014 Artem Iglikov <artem.iglikov@gmail.com>
# Copyright © 2014 Fabian Gundlach <320pointsguy@gmail.com>
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

"""Web server for administration of contests.

"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import base64
import json
import logging
import os
import pkg_resources
import re
import traceback
from datetime import datetime, timedelta
from StringIO import StringIO
import zipfile

from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError

import tornado.web
import tornado.locale

from cms import config, ServiceCoord, get_service_shards, get_service_address
from cms.io import WebService
from cms.db import Session, Contest, User, Announcement, Question, Message, \
    Submission, SubmissionResult, File, Task, Dataset, Attachment, Manager, \
    Testcase, SubmissionFormatElement, Statement
from cms.db.filecacher import FileCacher
from cms.grading import compute_changes_for_dataset
from cms.grading.tasktypes import get_task_type_class
from cms.grading.scoretypes import get_score_type_class
from cms.server import file_handler_gen, get_url_root, \
    CommonRequestHandler
from cmscommon.datetime import make_datetime, make_timestamp


logger = logging.getLogger(__name__)

class BaseHandler(CommonRequestHandler):
    """Base RequestHandler for this application.

    All the RequestHandler classes in this application should be a
    child of this class.

    """
    def render_params(self):
        """Return the default render params used by almost all handlers.

        return (dict): default render params

        """
        params = {}
        return params



class TrainingWebServer(WebService):
    """Service that runs the web server serving the managers.

    """

    def __init__(self, shard):
        parameters = {
            "login_url": "/",
            "template_path": pkg_resources.resource_filename(
                "cms.server", "templates/training"),
            "static_path": pkg_resources.resource_filename(
                "cms.server", "static"),
            "cookie_secret": base64.b64encode(config.secret_key),
            "debug": config.tornado_debug,
            "rpc_enabled": True,
        }

        super(TrainingWebServer, self).__init__(
            config.training_listen_port,
            _tws_handlers,
            parameters,
            shard=shard,
            listen_address=config.training_listen_address)

class MainHandler(BaseHandler):
    """Home page handler, with queue and workers statuses.

    """

    def get(self, contest_id=None):
        self.r_params = self.render_params()
        self.render("welcome.html", **self.r_params)



_tws_handlers = [
    (r"/", MainHandler),
]
