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

"""Web server for training

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
from cms.db import Session, Problem
from cms.db.filecacher import FileCacher
from cms.grading import compute_changes_for_dataset
from cms.grading.tasktypes import get_task_type_class
from cms.grading.scoretypes import get_score_type_class
from cms.server import file_handler_gen, get_url_root, \
    CommonRequestHandler
from cmscommon.datetime import make_datetime, make_timestamp


logger = logging.getLogger(__name__)

def create_training_contest():
    attrs = dict()
    attrs["name"] = "TrainingWebServer"
    attrs["description"] = "A specialized 'contest' for the training web server"
    attrs["allowed_localizations"] = []
    attrs["languages"] = []
    

    attrs["token_mode"] = 
    attrs["token_max_number"] = 
    attrs["token_min_interval"] = 
    attrs["token_gen_initial"] = 
    attrs["token_gen_number"] = 
    attrs["token_gen_interval"] = 
    attrs["token_gen_max"] = 

    attrs["max_submission_number"] = 
    attrs["max_user_test_number"] = 
    attrs["min_submission_interval"] = 
    attrs["min_user_test_interval"] = 

    attrs["start"] = 
    attrs["stop"] = 

    attrs["timezone"] = 
    attrs["per_user_time"] = 
    attrs["score_precision"] = 

    return Contest(**attrs)
    

class BaseHandler(CommonRequestHandler):
    """Base RequestHandler for this application.

    All the RequestHandler classes in this application should be a
    child of this class.

    """

    def prepare(self):
        """This method is executed at the beginning of each request.

        """
        # Attempt to update the contest and all its references
        # If this fails, the request terminates.
        self.set_header("Cache-Control", "no-cache, must-revalidate")

        self.sql_session = Session()
        self.sql_session.expire_all()
        
        contests = self.sql_session.query(Contest).\
                        filter(Contest.name == "TrainingWebServer") 

        assert len(contests) <= 1, "Many contests named training web server."

        if len(contests) == 0:
            try:
                self.contest = create_training_contest()
                self.sql_session.add(self.contest)
                self.sql_session.commit()
            except Exception as error:
                self.redirect("/")
                return
        else:
            self.contest = contests[0]

        if config.installed:
            localization_dir = os.path.join("/", "usr", "local", "share",
                                            "locale")
        else:
            localization_dir = os.path.join(os.path.dirname(__file__), "mo")
        if os.path.exists(localization_dir):
            tornado.locale.load_gettext_translations(localization_dir, "cms")

    def render_params(self):
        """Return the default render params used by almost all handlers.

        return (dict): default render params

        """
        params = {}
        params["timestamp"] = make_datetime()
        params["url_root"] = get_url_root(self.request.path)
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

        self.contest = 

        self.evaluation_service = self.connect_to(
            ServiceCoord("EvaluationService", 0))


class MainHandler(BaseHandler):
    """Home page handler, with queue and workers statuses.

    """

    def get(self, contest_id=None):
        self.r_params = self.render_params()
        self.r_params["q"] = self.sql_session.query(Problem).all()
        self.render("welcome.html", **self.r_params)

class AddProblemHandler(BaseHandler):
    """Adds a new problem.

    """
    def get(self):
        self.r_params = self.render_params()
        self.render("add_problem.html", **self.r_params)

    def post(self):
        try:
            attrs = dict()
            
            attrs["name"] = self.get_argument("name")
            attrs["title"] = self.get_argument("title")

            assert attrs.get("name") is not None, "No problem name specified."

            # Create the problem.
            problem = Problem(**attrs)
            self.sql_session.add(problem)
            self.sql_session.commit()
        except Exception as error:
            self.redirect("/problem/add")
            return

        self.redirect("/")

class SubmitHandler(BaseHandler):
    """Handles the received submissions.

    """
    @tornado.web.authenticated
    @actual_phase_required(0)
    def post(self, problem_name):
    """
        try:
            task = self.problem.get_task(task_name)
        except KeyError:
            raise tornado.web.HTTPError(404)

        # Add submitted files. After this, files is a dictionary indexed
        # by *our* filenames (something like "output01.txt" or
        # "taskname.%l", and whose value is a couple
        # (user_assigned_filename, content).
        files = {}
        for uploaded, data in self.request.files.iteritems():
            files[uploaded] = (data[0]["filename"], data[0]["body"])

        # If we allow partial submissions, implicitly we recover the
        # non-submitted files from the previous submission. And put them
        # in file_digests (i.e. like they have already been sent to FS).
        submission_lang = None
        file_digests = {}
        retrieved = 0

        # All checks done, submission accepted.

        # We now have to send all the files to the destination...
        try:
            for filename in files:
                digest = self.application.service.file_cacher.put_file_content(
                    files[filename][1],
                    "Submission file %s sent by %s at %d." % (
                        filename, self.current_user.username,
                        make_timestamp(self.timestamp)))
                file_digests[filename] = digest

        # In case of error, the server aborts the submission
        except Exception as error:
            self.redirect("/")
            return

        # All the files are stored, ready to submit!
        submission = Submission(self.timestamp,
                                submission_lang,
                                user=self.current_user,
                                task=task)

        for filename, digest in file_digests.items():
            self.sql_session.add(File(filename, digest, submission=submission))
        self.sql_session.add(submission)
        self.sql_session.commit()
        self.application.service.evaluation_service.new_submission(
            submission_id=submission.id)

        self.redirect("/")
    """
        pass

_tws_handlers = [
    (r"/", MainHandler),
    (r"/problem/add", AddProblemHandler),
    (r"/problem/submit", SubmitHandler),
]
