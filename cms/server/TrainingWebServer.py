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
import pickle
import io
import random

from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError

import tornado.web
import tornado.locale

from cms import config, ServiceCoord, get_service_shards, get_service_address,\
    DEFAULT_LANGUAGES, SOURCE_EXT_TO_LANGUAGE_MAP
from cms.io import WebService
from cms.db import Session, Contest, SubmissionFormatElement, Task, Dataset, \
    Testcase, Submission, User, File, ProblemSet, ProblemSetItem, UserSet, \
    UserSetItem, ProblemSetPin, ProblemSetToUserSet
from cms.db.filecacher import FileCacher
from cms.grading import compute_changes_for_dataset
from cms.grading.tasktypes import get_task_type_class, get_task_type
from cms.grading.scoretypes import get_score_type_class
from cms.server import file_handler_gen, get_url_root, \
    CommonRequestHandler
from cmscommon.datetime import make_datetime, make_timestamp


logger = logging.getLogger(__name__)

def admin_authenticated(foo):
    def func(self, *args, **kwargs):
        print('self is %s' % self)
        if self.current_user.item.is_admin == False:
            self.redirect("/")
        else:
            return foo(self, *args, **kwargs)
    return func


def xstr(src):
    if src:
        return str(src)
    else:
        return ""

def create_training_contest():
    attrs = dict()
    attrs["name"] = "TrainingWebServer"
    attrs["description"] = "A specialized 'contest' for the training web server"
    attrs["allowed_localizations"] = []
    attrs["languages"] = DEFAULT_LANGUAGES

    attrs["token_mode"] = "disabled"
    attrs["start"] = datetime(2000, 01, 01)
    attrs["stop"] = datetime(2100, 01, 01)
    attrs["score_precision"] = 0

    return Contest(**attrs)

def argument_reader(func, empty=None):
    """Return an helper method for reading and parsing form values.

    func (function): the parser and validator for the value.
    empty (object): the value to store if an empty string is retrieved.

    return (function): a function to be used as a method of a
        RequestHandler.

    """
    def helper(self, dest, name, empty=empty):
        """Read the argument called "name" and save it in "dest".

        self (RequestHandler): a thing with a get_argument method.
        dest (dict): a place to store the obtained value.
        name (string): the name of the argument and of the item.
        empty (object): overrides the default empty value.

        """
        value = self.get_argument(name, None)
        if value is None:
            return
        if value == "":
            dest[name] = empty
        else:
            dest[name] = func(value)
    return helper


class BaseHandler(CommonRequestHandler):
    """Base RequestHandler for this application.

    All the RequestHandler classes in this application should be a
    child of this class.

    """

    refresh_cookie = True

    def createIndividualUserSet(self, user):
        individualSets = self.sql_session.query(UserSetItem).\
                             filter(UserSetItem.user==user,
                                    UserSetItem.userSet.has(UserSet.setType==1))

        assert individualSets.count() <= 1
        if individualSets.count() == 0:
            attrs = {
                'name': user.username,
                'title': xstr(user.first_name) + " " + xstr(user.last_name),
                'setType': 1
            }
            individualSet = UserSet(**attrs)
            self.sql_session.add(individualSet)

            attrs = {
                'user': user,
                'userSet': individualSet
            }
            membership = UserSetItem(**attrs)
            self.sql_session.add(membership)

    def createSpecialUserSets(self):
        # Ensure the all users group exists
        userSets = self.sql_session.query(UserSet).filter(UserSet.setType==2)
        assert userSets.count() <= 1
        if userSets.count() == 0:
            attrs = {
                'name': "AllUsers",
                'title': "All Users",
                'setType': 2
            }
            allUsersSet = UserSet(**attrs)
            self.sql_session.add(allUsersSet)

            # Ensure that each user has their own userset and is in the all users set
            for user in self.contest.users:
                # self.createIndividualUserSet(user)

                allUsersMemberships = self.sql_session.query(UserSetItem).\
                                           filter(UserSetItem.user==user,
                                                  UserSetItem.userSet==allUsersSet)

                assert allUsersMemberships.count() <= 1
                if allUsersMemberships.count() == 0:
                    allUsersSet.items.append(user.item)

            self.sql_session.commit()

    def create_admin(self):
        num_admin = self.sql_session.query(User).\
                    filter(User.contest == self.contest).\
                    filter(User.username == 'admin').count()

        if num_admin == 1:
            return

        attrs = {
            'first_name' : 'admin',
            'last_name'  : 'adminson',
            'username'   : 'admin',
            'password'   : 'password',
            'contest'    : self.contest
        } 

       
        # Create the admin.
        admin = User(**attrs)
        self.sql_session.add(admin)

        # Add the user to the all users group
        attrs = {
            'user': admin,
            'is_admin' : True,
        }
        setitem = UserSetItem(**attrs) 
        self.sql_session.add(setitem)
        self.all_users.items.append(setitem)            


        # Add the user to its own unique userset
        attrs = {
            'name': admin.username,
            'title': xstr(admin.first_name) + " " + xstr(admin.last_name),
            'setType': 1
        }
        individualSet = UserSet(**attrs)
        self.sql_session.add(individualSet)
        individualSet.items.append(setitem)

        self.sql_session.commit()
        

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

        assert contests.count() <= 1, "Many contests named training web server."

        if contests.count() == 0:
            try:
                self.contest = create_training_contest()
                self.sql_session.add(self.contest)
                self.sql_session.commit()
            except Exception as error:
                print(error)
                self.set_status(500)
                return
        else:
            self.contest = contests[0]

        self.createSpecialUserSets()

        self.all_users = self.sql_session.query(UserSet).filter(UserSet.setType==2).one()

        self.create_admin()

        if config.installed:
            localization_dir = os.path.join("/", "usr", "local", "share",
                                            "locale")
        else:
            localization_dir = os.path.join(os.path.dirname(__file__), "mo")
        if os.path.exists(localization_dir):
            tornado.locale.load_gettext_translations(localization_dir, "cms")

        self.timestamp = make_datetime()
        self.r_params = self.render_params()

    def get_current_user(self):
        """Gets the current user logged in from the cookies

        If a valid cookie is retrieved, return a User object with the
        username specified in the cookie. Otherwise, return None.

        """
        if self.get_secure_cookie("login") is None:
            return None

        # Parse cookie.
        try:
            cookie = pickle.loads(self.get_secure_cookie("login"))
            username = cookie[0]
            password = cookie[1]
            last_update = make_datetime(cookie[2])
        except:
            self.clear_cookie("login")
            return None

        # Check if the cookie is expired.
        if self.timestamp - last_update > \
                timedelta(seconds=config.cookie_duration):
            self.clear_cookie("login")
            return None

        # Load the user from DB.
        user = self.sql_session.query(User)\
            .filter(User.contest == self.contest)\
            .filter(User.username == username).first()

        # Check if user exists and is allowed to login.
        if user is None or user.password != password:
            self.clear_cookie("login")
            return None

        if self.refresh_cookie:
            self.set_secure_cookie("login",
                                   pickle.dumps((user.username,
                                                 user.password,
                                                 make_timestamp())),
                                   expires_days=None)
        return user

    def render_params(self):
        """Return the default render params used by almost all handlers.

        return (dict): default render params

        """
        params = {}
        params["timestamp"] = make_datetime()
        params["url_root"] = get_url_root(self.request.path)
        params["current_user"] = self.current_user
        return params

    def get_task_by_id(self, task_id):
        if not task_id.isdigit():
            raise KeyError

        for task in self.contest.tasks:
            if task.id == int(task_id):
                return task
        raise KeyError

    def get_submission_format(self, dest):
        """Parse the submission format.

        Using the two arguments "submission_format_choice" and
        "submission_format" set the "submission_format" item of the
        given dictionary.

        dest (dict): a place to store the result.

        """
        choice = self.get_argument("submission_format_choice", "other")
        if choice == "simple":
            filename = "%s.%%l" % dest["name"]
            format_ = [SubmissionFormatElement(filename)]
        elif choice == "other":
            value = self.get_argument("submission_format", "[]")
            if value == "":
                value = "[]"
            format_ = []
            try:
                for filename in json.loads(value):
                    format_ += [SubmissionFormatElement(filename)]
            except ValueError:
                raise ValueError("Submission format not recognized.")
        else:
            raise ValueError("Submission format not recognized.")
        dest["submission_format"] = format_

    def get_task_type(self, dest, name, params):
        """Parse the task type.

        Parse the arguments to get the task type and its parameters,
        and fill them in the "task_type" and "task_type_parameters"
        items of the given dictionary.

        dest (dict): a place to store the result.
        name (string): the name of the argument that holds the task
            type name.
        params (string): the prefix of the names of the arguments that
            hold the parameters.

        """
        name = self.get_argument(name, None)
        if name is None:
            raise ValueError("Task type not found.")
        try:
            class_ = get_task_type_class(name)
        except KeyError:
            raise ValueError("Task type not recognized: %s." % name)
        params = json.dumps(class_.parse_handler(self, params + name + "_"))
        dest["task_type"] = name
        dest["task_type_parameters"] = params


    get_string = argument_reader(lambda a: a, empty="")

    def get_time_limit(self, dest, field):
        """Parse the time limit.

        Read the argument with the given name and use its value to set
        the "time_limit" item of the given dictionary.

        dest (dict): a place to store the result.
        field (string): the name of the argument to use.

        """
        value = self.get_argument(field, None)
        if value is None:
            return
        if value == "":
            dest["time_limit"] = None
        else:
            try:
                value = float(value)
            except:
                raise ValueError("Can't cast %s to float." % value)
            if not 0 <= value < float("+inf"):
                raise ValueError("Time limit out of range.")
            dest["time_limit"] = value

    def get_memory_limit(self, dest, field):
        """Parse the memory limit.

        Read the argument with the given name and use its value to set
        the "memory_limit" item of the given dictionary.

        dest (dict): a place to store the result.
        field (string): the name of the argument to use.

        """
        value = self.get_argument(field, None)
        if value is None:
            return
        if value == "":
            dest["memory_limit"] = None
        else:
            try:
                value = int(value)
            except:
                raise ValueError("Can't cast %s to float." % value)
            if not 0 < value:
                raise ValueError("Invalid memory limit.")
            dest["memory_limit"] = value

    def get_score_type(self, dest, name, params):
        """Parse the score type.

        Parse the arguments to get the score type and its parameters,
        and fill them in the "score_type" and "score_type_parameters"
        items of the given dictionary.

        dest (dict): a place to store the result.
        name (string): the name of the argument that holds the score
            type name.
        params (string): the name of the argument that hold the
            parameters.

        """
        name = self.get_argument(name, None)
        if name is None:
            raise ValueError("Score type not found.")
        try:
            get_score_type_class(name)
        except KeyError:
            raise ValueError("Score type not recognized: %s." % name)
        params = self.get_argument(params, None)
        if params is None:
            raise ValueError("Score type parameters not found.")
        dest["score_type"] = name
        dest["score_type_parameters"] = params

    def check_signup_valid_input(self, attrs):
        assert attrs.get("username") is not None, \
                "No username specified."
        assert attrs.get("password") is not None, \
                "No password specified."

class TrainingWebServer(WebService):
    """Service that runs the web server serving the managers.

    """

    def __init__(self, shard):
        parameters = {
            "login_url": "/login",
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

        self.evaluation_service = self.connect_to(
            ServiceCoord("EvaluationService", 0))

        self.file_cacher = FileCacher(self)


class MainHandler(BaseHandler):
    """Home page handler

    """
    @tornado.web.authenticated
    def get(self):
        self.r_params["sets"] = [self.sql_session.query(ProblemSet).
                                 filter(ProblemSet.id==pin.problemSet_id).one() 
                                 for pin in self.current_user.pins]
        self.r_params["active_sidebar_item"] = "home"
        self.render("home.html", **self.r_params)

class ProblemListHandler(BaseHandler):
    """Problem list handler

    """
    @tornado.web.authenticated
    def get(self):
        self.r_params["sets"] = self.sql_session.query(ProblemSet)
        self.r_params["active_sidebar_item"] = "problems"
        self.render("contestant_problemlist.html", **self.r_params)

class LoginHandler(BaseHandler):
    """Login handler.

    """
    def get(self):
        self.get_string(self.r_params, "error")
        self.render("login.html", **self.r_params)

    def post(self):
        username = self.get_argument("username", "")
        password = self.get_argument("password", "")
        user = self.sql_session.query(User)\
            .filter(User.contest == self.contest)\
            .filter(User.username == username).first()

        if user is None:
            self.redirect("/login?error=Invalid Username")
            return

        if user.password != password:
            self.redirect("login?error=Invalid Password")
            return

        self.set_secure_cookie("login",
                               pickle.dumps((user.username,
                                             user.password,
                                             make_timestamp())),
                               expires_days=None)
        self.redirect("/")

class SignupHandler(BaseHandler):
    def post(self):
        try:
            attrs = dict()

            self.get_string(attrs, "first_name")
            self.get_string(attrs, "last_name")
            self.get_string(attrs, "username", empty=None)
            self.get_string(attrs, "password", empty=None)
            self.get_string(attrs, "email")

            self.check_signup_valid_input(attrs)

            # Create the user.
            attrs["contest"] = self.contest
            user = User(**attrs)
            self.sql_session.add(user)

            # Add the user to the all users group
            attrs = {
                'user': user
            }
            setitem = UserSetItem(**attrs) 
            self.sql_session.add(setitem)
            self.all_users.items.append(setitem)            


            # Add the user to its own unique userset
            attrs = {
                'name': user.username,
                'title': xstr(user.first_name) + " " + xstr(user.last_name),
                'setType': 1
            }
            individualSet = UserSet(**attrs)
            self.sql_session.add(individualSet)
            individualSet.items.append(setitem)

            self.sql_session.commit()

        except Exception as error:
            print(error)
            self.redirect("/signup")
            return

        self.redirect("/")

class LogoutHandler(BaseHandler):
    """Logout handler.

    """
    def get(self):
        self.clear_cookie("login")
        self.redirect("/")

class AdminMainHandler(BaseHandler):
    """Admin Home page handler
    
    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params = self.render_params()
        self.r_params["sets"] = self.sql_session.query(ProblemSet)
        self.r_params["tasks"] = self.contest.tasks
        self.render("admin_problems.html", **self.r_params)

class AddProblemHandler(BaseHandler):
    """Adds a new problem.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.render("add_task.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self):
        try:
            attrs = dict()

            self.get_string(attrs, "name", empty=None)
            self.get_string(attrs, "title")

            assert attrs.get("name") is not None, "No task name specified."

            self.get_string(attrs, "primary_statements")
            self.get_submission_format(attrs)

            attrs["token_mode"] = "disabled"
            attrs["score_precision"] = 0

            # Create the task.
            attrs["num"] = len(self.contest.tasks)
            attrs["contest"] = self.contest
            task = Task(**attrs)
            self.sql_session.add(task)

        except Exception as error:
            self.redirect("/admin/problem/add")
            print(error)
            return

        try:
            attrs = dict()

            self.get_time_limit(attrs, "time_limit")
            self.get_memory_limit(attrs, "memory_limit")
            self.get_task_type(attrs, "task_type", "TaskTypeOptions_")
            self.get_score_type(attrs, "score_type", "score_type_parameters")

            # Create its first dataset.
            attrs["description"] = "Default"
            attrs["autojudge"] = True
            attrs["task"] = task
            dataset = Dataset(**attrs)
            self.sql_session.add(dataset)

            # Make the dataset active. Life works better that way.
            task.active_dataset = dataset
            self.sql_session.commit()

        except Exception as error:
            print(error)
            self.redirect("/admin/problem/add")
            return

        self.redirect("/admin/problem/%s" % task.id)

class ProblemHandler(BaseHandler):
    """Shows the data of a task.

    """

    @tornado.web.authenticated
    def get(self, task_id):
        try:
            task = self.get_task_by_id(task_id)
        except KeyError:
            raise tornado.web.HTTPError(404)

        # TODO: We can support multiple languages here.
        # see ContestWebServer
        self.render("task_description.html",
                    task=task, **self.r_params)

class AdminProblemHandler(BaseHandler):
    """Shows the data of a task.

    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self, task_id):
        try:
            task = self.get_task_by_id(task_id)
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.render("admin_problem.html",
                    task=task, **self.r_params)

class DeleteProblemHandler(BaseHandler):
    """Deletes a task.

    """

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, task_id):
        try:
            task = self.get_task_by_id(task_id)
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.sql_session.delete(task)
        self.sql_session.commit()

        self.redirect("/")

# Does not edit or load the submission format choice
class EditProblemHandler(BaseHandler):
    """Edits a task.
    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self, task_id):
        try:
            task = self.get_task_by_id(task_id)
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.render("edit_task.html", 
                    task=task, **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, task_id):
        try:
            task = self.get_task_by_id(task_id)
        except KeyError:
            raise tornado.web.HTTPError(404)

        try:
            attrs = dict()

            # get input
            self.get_string(attrs, "name", empty=None)

            assert attrs.get("name") is not None, "No task name specified."

            self.get_string(attrs, "title")
            self.get_string(attrs, "primary_statements")
            self.get_string(attrs, "time_limit")
            self.get_string(attrs, "memory_limit")
            self.get_string(attrs, "task_type")
            self.get_string(attrs, "score_type")
            self.get_string(attrs, "score_type_parameters")

            # save input to task
            task.name = attrs.get("name")
            task.title = attrs.get("title")
            task.primary_statements = attrs.get("primary_statements")
            task.active_dataset.time_limit = attrs.get("time_limit")
            task.active_dataset.memory_limit = attrs.get("memory_limit")
            task.active_dataset.task_type = attrs.get("task_type")
            task.active_dataset.score_type = attrs.get("score_type")
            task.active_dataset.score_type_parameters = attrs.get("score_type_parameters")
            
            self.sql_session.commit()

        except Exception as error:
            self.redirect("/admin/problem/%s/edit" % task_id)
            print(error)
            return

        self.redirect("/")

class AddTestHandler(BaseHandler):
    """Add a testcase to a dataset.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self, task_id):
        task = self.get_task_by_id(task_id)
        dataset = task.active_dataset

        self.r_params = self.render_params()
        self.r_params["task"] = task
        self.r_params["dataset"] = dataset
        self.render("add_testcase.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, task_id):
        task = self.get_task_by_id(task_id)
        dataset = task.active_dataset

        codename = self.get_argument("codename")

        try:
            input_ = self.request.files["input"][0]
            output = self.request.files["output"][0]
        except KeyError:
            print("Couldn't find files")
            self.redirect("/admin/problem/%s/test" % task_id)
            return

        public = self.get_argument("public", None) is not None

        try:
            input_digest = \
                self.application.service.file_cacher.put_file_content(
                    input_["body"],
                    "Testcase input for task %s" % task.name)
            output_digest = \
                self.application.service.file_cacher.put_file_content(
                    output["body"],
                    "Testcase output for task %s" % task.name)
            testcase = Testcase(codename, public, input_digest,
                                    output_digest, dataset=dataset)
            self.sql_session.add(testcase)
            self.sql_session.commit()
        except Exception as error:
            print(error)
            self.redirect("/admin/problem/%s/test" % task_id)
            return

        self.redirect("/admin/problem/%s" % task.id)

class DeleteTestHandler(BaseHandler):
    """Delete a testcase.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def post(self, task_id, test_id):
        test = self.sql_session.query(Testcase).
               filter(Testcase.id == test_id).one()
        try:
            self.sql_session.delete(test)
            self.sql_session.commit()
        except Exception as error:
            print(error)
            self.redirect("/admin/problem/%s" % task_id)
            return

        self.redirect("/admin/problem/%s" % task_id)

class SubmitHandler(BaseHandler):
    """Handles the received submissions.

    """
    @tornado.web.authenticated
    def post(self, task_id):
        try:
            task = self.get_task_by_id(task_id)
        except KeyError:
            raise tornado.web.HTTPError(404)

        # Alias for easy access
        contest = self.contest
        last_submission_t = self.sql_session.query(Submission)\
                           .filter(Submission.task == task)\
                           .filter(Submission.user == self.current_user)\
                           .order_by(Submission.timestamp.desc()).first()


        # Ensure that the user did not submit multiple files with the
        # same name.
        if any(len(filename) != 1 for filename in self.request.files.values()):
            print("Multiple files with the same name")
            self.redirect("/problem/%s" % task.id)
            return

        # This ensure that the user sent one file for every name in
        # submission format and no more. Less is acceptable if task
        # type says so.
        task_type = get_task_type(dataset=task.active_dataset)
        required = set([sfe.filename for sfe in task.submission_format])
        provided = set(self.request.files.keys())
        if not (required == provided or (task_type.ALLOW_PARTIAL_SUBMISSION
                                         and required.issuperset(provided))):
            print("More than one file for every name.")
            self.redirect("/problem/%s" % task.id)
            return

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
        if task_type.ALLOW_PARTIAL_SUBMISSION and \
                last_submission_t is not None:
            for filename in required.difference(provided):
                if filename in last_submission_t.files:
                    # If we retrieve a language-dependent file from
                    # last submission, we take not that language must
                    # be the same.
                    if "%l" in filename:
                        submission_lang = last_submission_t.language
                    file_digests[filename] = \
                        last_submission_t.files[filename].digest
                    retrieved += 1

        # We need to ensure that everytime we have a .%l in our
        # filenames, the user has the extension of an allowed
        # language, and that all these are the same (i.e., no
        # mixed-language submissions).
        def which_language(user_filename):
            """Determine the language of user_filename from its
            extension.

            user_filename (string): the file to test.
            return (string): the extension of user_filename, or None
                             if it is not a recognized language.

            """
            for source_ext, language in SOURCE_EXT_TO_LANGUAGE_MAP.iteritems():
                if user_filename.endswith(source_ext):
                    return language
            return None

        error = None
        for our_filename in files:
            user_filename = files[our_filename][0]
            if our_filename.find(".%l") != -1:
                lang = which_language(user_filename)
                if lang is None:
                    #error = self._("Cannot recognize submission's language.")
                    error = 1
                    break
                elif submission_lang is not None and \
                        submission_lang != lang:
                    #error = self._("All sources must be in the same language.")
                    error = 1
                    break
                elif lang not in contest.languages:
                    error = 1
                    #error = self._(
                    #    "Language %s not allowed in this contest." % lang)
                    break
                else:
                    submission_lang = lang
        if error is not None:
            print("Incorrect language extension")
            self.redirect("/problem/%s" % task.id)
            return

        # Check if submitted files are small enough.
        if any([len(f[1]) > config.max_submission_length
                for f in files.values()]):
            print("Files are too big")
            self.redirect("/problem/%s" % task.id)
            return

        # All checks done, submission accepted.

        # Attempt to store the submission locally to be able to
        # recover a failure.
        if config.submit_local_copy:
            try:
                path = os.path.join(
                    config.submit_local_copy_path.replace("%s",
                                                          config.data_dir),
                    self.current_user.username)
                if not os.path.exists(path):
                    os.makedirs(path)
                # Pickle in ASCII format produces str, not unicode,
                # therefore we open the file in binary mode.
                with io.open(
                        os.path.join(path,
                                     "%d" % make_timestamp(self.timestamp)),
                        "wb") as file_:
                    pickle.dump((self.contest.id,
                                 self.current_user.id,
                                 task.id,
                                 files), file_)
            except Exception as error:
                # TODO: add error message
                pass

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
            print(error)
            self.redirect("/problem/%s" % task.id)
            return

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


        self.redirect("/problem/%s/submissions" % task.id)

class SubmissionsHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, task_id):
        try:
            task = self.get_task_by_id(task_id)
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.r_params["submissions"] = self.sql_session.query(Submission)\
                                      .filter(Submission.task == task)\
                                      .filter(Submission.user == self.current_user)\
                                      .order_by(Submission.timestamp.desc())
        self.r_params["task"] = task

        self.render("task_submissions.html", **self.r_params)

class ProblemSetPinHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self, set_id, action, unused):
        if action == "unpin":
            self.sql_session.query(ProblemSetPin).filter(ProblemSetPin.problemSet_id==set_id,
                                                         ProblemSetPin.user_id==self.current_user.id).delete()

        elif action == "pin":
            attrs = {
                'problemSet': self.sql_session.query(ProblemSet).filter(ProblemSet.id==set_id).one(),
                'user': self.current_user,
            }
            problemSetPin = ProblemSetPin(**attrs)
            self.sql_session.add(problemSetPin)

        self.sql_session.commit()

class AddProblemSetHandler(BaseHandler):
    """Adds a new problem set.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        tasks = self.sql_session.query(Task.id, Task.title).all()
        self.r_params['taskdata'] = tasks
        self.render("add_problemset.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self):
        try:
            attrs = dict()

            self.get_string(attrs, "name", empty=None)
            self.get_string(attrs, "title")
            self.get_string(attrs, "num")
            attrs["contest"] = self.contest
            #attrs["contest_id"] = self.contest.id
            #TODO: CHANGE AFTER DEMO
            random.seed()
            attrs["num"] = random.randint(1,100000)
            assert attrs.get("name") is not None, "No set name specified."

            print(attrs["num"])

            problemset = ProblemSet(**attrs)
            self.sql_session.add(problemset)

            working = dict()
            self.get_string(working, "problemids")
            problemids = working["problemids"].strip().split()

            assert reduce(lambda x, y: x and y.isdigit(), problemids, True), "Not all problem ids are integers"

            problemids = map(int, problemids)

            ## TODO: Ensure all problem ids are actually problems.

            for index, problemid in enumerate(problemids):
                task = self.sql_session.query(Task).filter(Task.id==problemid).one()
                attrs = {"num":index, "problemSet":problemset, "task":task}
                problemsetitem = ProblemSetItem(**attrs)
                self.sql_session.add(problemsetitem)

            self.sql_session.commit()

        except Exception as error:
            self.redirect("/admin/problemset/add")
            print(error)
            return

        self.redirect("/admin/problems")

class DeleteProblemSetHandler(BaseHandler):
    """Deletes a problem set.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def post(self, set_id):
        try:
            problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.id==set_id).one()

            self.sql_session.delete(problemset)
            self.sql_session.commit()
        except Exception as error:
            print(error)
        self.redirect("/admin/problems")

class EditProblemSetHandler(BaseHandler):
    """Edits a problem set.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self, set_id):
        problemSet = self.sql_session.query(ProblemSet).filter(ProblemSet.id==set_id).one()
        selectedids = set([x.task_id for x in problemSet.items])

        tasks = self.sql_session.query(Task.id, Task.name).all()

        seltasks = filter(lambda x: x[0] in selectedids, tasks)
        unseltasks = filter(lambda x: x[0] not in selectedids, tasks)

        self.r_params["problemset"] = problemSet
        self.r_params["seltaskdata"] = seltasks
        self.r_params["unseltaskdata"] = unseltasks

        self.render("edit_problemset.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, set_id):
        try:
            problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.id==set_id).one()
        except Exception as error:
            print(error)
            self.redirect("/admin/problemset/%d/edit" % set_id)
        try:
            attrs = dict()
            self.get_string(attrs, "name", empty=None)
            self.get_string(attrs, "title", empty=None)
            self.get_string(attrs, "problemids", empty=None)


            if attrs["name"] is not None:
                problemset.name = attrs["name"]

            if attrs["title"] is not None:
                problemset.title = attrs["title"]

            if attrs["problemids"] is not None:
                for item in problemset.items:
                    self.sql_session.delete(item)

                problemids = attrs["problemids"].strip().split()

                assert reduce(lambda x, y: x and y.isdigit(), problemids, True), "Not all problem ids are integers"

                problemids = map(int, problemids)

                for index, problemid in enumerate(problemids):
                    task = self.sql_session.query(Task).filter(Task.id==problemid).one()
                    attrs = {"num":index, "problemSet":problemset, "task":task}
                    problemsetitem = ProblemSetItem(**attrs)
                    self.sql_session.add(problemsetitem)
            self.sql_session.commit()

        except Exception as error:
            print(error)
            self.redirect("/admin/problemset/%d/edit" % set_id)

        self.redirect("/admin/problems")

class AdminUserHandler(BaseHandler):
    """Admin Users page handler
    
    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params = self.render_params()
        self.r_params["users"] = self.sql_session.query(User)
        self.render("admin_users.html", **self.r_params)

class UserHandler(BaseHandler):
    """Shows the data of a user.

    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self, user_id):
        try:
            usersetitem = self.sql_session.query(UserSetItem)\
            .filter(UserSetItem.user_id==user_id).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.render("user_description.html",
                    usersetitem=usersetitem, **self.r_params)

class EditUserHandler(BaseHandler):
    """Edits a task.
    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self, user_id):
        try:
            usersetitem = self.sql_session.query(UserSetItem)\
            .filter(UserSetItem.user_id==user_id).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.render("edit_user.html", 
                    usersetitem=usersetitem, **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, user_id):
        try:
            user = self.sql_session.query(User)\
            .filter(User.id==user_id).one()
            usersetitem = self.sql_session.query(UserSetItem)\
            .filter(UserSetItem.user_id==user_id).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        try:
            attrs = dict()

            # get input
            self.get_string(attrs, "first_name")
            self.get_string(attrs, "last_name")
            self.get_string(attrs, "username", empty=None)
            self.get_string(attrs, "password", empty=None)
            self.get_string(attrs, "email")
            is_admin_choice = self.get_argument("is_admin")

            self.check_signup_valid_input(attrs)

            # save input to user
            user.first_name = attrs.get("first_name")
            user.last_name = attrs.get("last_name")
            user.username = attrs.get("username")
            user.password = attrs.get("password")
            user.email = attrs.get("email")
            # save input to usersetitem
            usersetitem.is_admin = is_admin_choice

            self.sql_session.commit()

        except Exception as error:
            self.redirect("/admin/user/%s/edit" % user_id)
            print(error)
            return

        self.redirect("/admin/users")

class DeleteAccountHandler(BaseHandler):
    """Deletes the current user's account.

    """

    @tornado.web.authenticated
    def post(self):
        usersetitem = self.sql_session.query(UserSetItem)\
                     .filter(UserSetItem.user==self.current_user).one()

        self.sql_session.delete(usersetitem)
        self.sql_session.delete(self.current_user)
        self.sql_session.commit()

        self.redirect("/login")

class DeleteUserHandler(BaseHandler):
    """Deletes a user.

    """

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, user_id):
        try:
            usersetitem = self.sql_session.query(UserSetItem)\
            .filter(UserSetItem.user_id==user_id).one()
            user = self.sql_session.query(User)\
            .filter(User.id==user_id).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.sql_session.delete(usersetitem)
        self.sql_session.delete(user)
        self.sql_session.commit()

        self.redirect("/admin/users")

class ViewUserSetsHandler(BaseHandler):
    """View all user sets.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        # TODO: query UserSet instead
        self.r_params["sets"] = self.sql_session.query(UserSet)
        self.render("view_usersets.html", **self.r_params)

class AddUserSetHandler(BaseHandler):
    """Adds a new user set.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params["users"] = self.sql_session.query(User)
        self.r_params["problem_sets"] = self.sql_session.query(ProblemSet)
        self.render("add_userset.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self):
        try:
            attrs = dict()

            self.get_string(attrs, "name", empty=None)
            assert attrs.get("name") is not None, "No set name specified."
            self.get_string(attrs, "title")

            userset = UserSet(**attrs)
            self.sql_session.add(userset)

            # get list of user checked boxs
            users = self.request.arguments['add_users']

            # create userSetItems for each user
            for username in users:
                user = self.sql_session.query(User).\
                       filter(Contest.id == self.contest.id).\
                       filter(User.username==username).one()
                userset.items.append(user.item) 

            # get list of problem set checked boxs
            #problemsets = self.request.arguments['add_problem_sets']

            # at the moment, this says each problemset can only be set to ONE userset
            # TODO: change problemset table to allow many to many relationship equivalent
            #for problemsetname in problemsets:
                # print("problemsetname <"+problemsetname+">")
                #problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.name==problemsetname).one()
                #problemset.userset = userset

            self.sql_session.commit()

        except Exception as error:
            self.redirect("/")
            print(error)
            return

        self.redirect("/admin/usersets")

class UserInfoHandler(BaseHandler):
    """Info about the current user.
       User can edit their own info.
    """

    @tornado.web.authenticated
    def get(self):
        self.r_params["active_sidebar_item"] = ""
        self.render("user_info.html", **self.r_params)

    @tornado.web.authenticated
    def post(self):
        try:
            attrs = dict()

            user = self.current_user

            user.first_name = self.get_argument("first_name", "")
            user.last_name = self.get_argument("last_name", "")
            user.email = self.get_argument("email", "")

            if self.get_argument("password", "") != "":
                user.password = self.get_argument("password", "")

            userset = self.sql_session.query(UserSet).\
                      filter(UserSet.setType == 1).\
                      filter(UserSet.name == user.username).one()

            userset.title = xstr(user.first_name) + " " + xstr(user.last_name)

            self.sql_session.commit()

        except Exception as error:
            print(error)
            self.redirect("/user")
            return

        self.redirect("/user")
        

_tws_handlers = [
    (r"/", MainHandler),
    (r"/problems", ProblemListHandler),
    (r"/login", LoginHandler),
    (r"/signup", SignupHandler),
    (r"/logout", LogoutHandler),
    (r"/problem/([0-9]+)", ProblemHandler),
    (r"/problem/([0-9]+)/submit", SubmitHandler),
    (r"/problem/([0-9]+)/submissions", SubmissionsHandler),
    (r"/problemset/([0-9]+)/((un)?pin)", ProblemSetPinHandler),
    (r"/user", UserInfoHandler),
    (r"/user/delete", DeleteAccountHandler),
    (r"/admin/problems", AdminMainHandler),
    (r"/admin/problem/([0-9]+)", AdminProblemHandler),
    (r"/admin/problem/add", AddProblemHandler),
    (r"/admin/problem/([0-9]+)/delete", DeleteProblemHandler),
    (r"/admin/problem/([0-9]+)/edit", EditProblemHandler),
    (r"/admin/problem/([0-9]+)/test/add", AddTestHandler),
    (r"/admin/problem/([0-9]+)/test/delete", DeleteTestHandler),
    #(r"/admin/problemset/([0-9]+)", AdminProblemSetHandler),
    (r"/admin/problemset/add", AddProblemSetHandler),
    (r"/admin/problemset/([0-9]+)/delete", DeleteProblemSetHandler),
    (r"/admin/problemset/([0-9]+)/edit", EditProblemSetHandler),
    (r"/admin/users", AdminUserHandler),
    (r"/admin/user/([0-9]+)", UserHandler),
    (r"/admin/user/([0-9]+)/edit", EditUserHandler),
    (r"/admin/user/([0-9]+)/delete", DeleteUserHandler),
    (r"/admin/usersets", ViewUserSetsHandler),
    (r"/admin/userset/add", AddUserSetHandler),
]
