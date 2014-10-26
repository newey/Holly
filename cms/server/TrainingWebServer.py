# -*- coding: utf-8 -*-

# Contest Management System - http://cms-dev.github.io/
# Copyright © 2010-2013 Giovanni Mascellani <mascellani@poisson.phc.unipi.it>
# Copyright © 2010-2014 Stefano Maggiolo <s.maggiolo@gmail.com>
# Copyright © 2010-2012 Matteo Boscariol <boscarim@hotmail.com>
# Copyright © 2012-2014 Luca Wehrstedt <luca.wehrstedt@gmail.com>
# Copyright © 2014 Artem Iglikov <artem.iglikov@gmail.com>
# Copyright © 2014 Fabian Gundlach <320pointsguy@gmail.com>
#
# This program is free software: you can eedistribute it and/or modify
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
from sets import Set
import string
import smtplib
from email.mime.text import MIMEText
import traceback
from sqlalchemy import func
from datetime import datetime, timedelta
from StringIO import StringIO
import zipfile
import pickle
import io
import random
import email.utils

from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError

import tornado.web
import tornado.locale

from cms import config, ServiceCoord, get_service_shards, get_service_address,\
    DEFAULT_LANGUAGES, SOURCE_EXT_TO_LANGUAGE_MAP
from cms.io import WebService
from cms.db import Session, Contest, SubmissionFormatElement, Task, Dataset, \
    Testcase, Submission, User, File, ProblemSet, UserSet, SubmissionResult
from cms.db.filecacher import FileCacher
from cms.grading import compute_changes_for_dataset
from cms.grading.tasktypes import get_task_type_class, get_task_type
from cms.grading.scoretypes import get_score_type_class, get_score_type
from cms.server import file_handler_gen, get_url_root, \
    CommonRequestHandler
from cmscommon.datetime import make_datetime, make_timestamp


logger = logging.getLogger(__name__)

def admin_authenticated(foo):
    def func(self, *args, **kwargs):
        if not self.current_user.is_training_admin:
            self.redirect("/?error=You are not an admin.")
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

def parse_datetime(value):
    """Parse and validate a datetime (in pseudo-ISO8601)."""
    if '.' not in value:
        value += ".0"
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
    except:
        raise ValueError("Can't cast %s to datetime." % value)

def send_mail(mime_message):
    """Sends a MIME message as configured in cms.conf, and will ignore messages if message sending
    is turned off in the config.

    mime_message (email.mime.*): message to send, must have 'To' field defined.

    return (boolean): True if a message was send, False otherwise

    """
    if config.training_send_mail:
        try:
            mime_message['From'] = config.training_email_address
            s = smtplib.SMTP(config.training_smtp_server_address, config.training_smtp_server_port)
            if config.training_smtp_server_use_tls:
                s.starttls()
                s.ehlo()
            if config.training_smtp_server_authenticate:
                s.login(config.training_smtp_server_username, config.training_smtp_server_password)
            s.sendmail(mime_message['From'], [mime_message['To']], mime_message.as_string())
            s.quit()
            return True
        except smtplib.SMTPServerDisconnected:
            logger.exception("SMTP server disconnected while sending message")
        except smtplib.SMTPSenderRefused:
            logger.exception("SMTP server refused the sender address")
        except smtplib.SMTPRecipientsRefused:
            logger.exception("SMTP server refused the recipient addresses")
        except smtplib.SMTPDataError:
            logger.exception("SMTP server refused the message data")
        except smtplib.SMTPConnectError:
            logger.exception("SMTP server refused the connection")
        except smtplib.SMTPHeloError:
            logger.exception("SMTP server refused our HELO message")
        except smtplib.SMTPAuthenticationError:
            logger.exception("SMTP server refused Authentication")
        except Exception as e:
            logger.exception("caught: %s" % e.message)
    return False


class BaseHandler(CommonRequestHandler):
    """Base RequestHandler for this application.

    All the RequestHandler classes in this application should be a
    child of this class.

    """

    refresh_cookie = True

    def createIndividualUserSet(self, user):
        individualSets = self.sql_session.query(UserSet).\
                             filter(UserSet.setType==1,
                                    UserSet.users.contains(user))

        assert individualSets.count() <= 1
        if individualSets.count() == 0:
            attrs = {
                'name': user.username,
                'title': xstr(user.first_name) + " " + xstr(user.last_name),
                'setType': 1,
                'users': [user]
            }
            individualSet = UserSet(**attrs)
            self.sql_session.add(individualSet)

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
        else:
            allUsersSet = userSets[0]

        # Ensure that each user has their own userset and is in the all users set
        for user in self.contest.users:
            self.createIndividualUserSet(user)

            if user not in allUsersSet.users:
                allUsersSet.users.append(user)

            self.sql_session.commit()

    def create_admin(self):
        num_admin = self.sql_session.query(User).\
                    filter(User.contest == self.contest,
                           User.username == 'admin',
                           User.is_training_admin == True).count()

        if num_admin == 1:
            return

        attrs = {
            'first_name'       : 'admin',
            'last_name'        : 'adminson',
            'username'         : 'admin',
            'password'         : 'password',
            'is_training_admin': True,
            'contest'          : self.contest
        } 

       
        # Create the admin.
        admin = User(**attrs)
        self.sql_session.add(admin)

        # Add the user to the all users group
        self.all_users.users.append(admin)


        # Add the user to its own unique userset
        attrs = {
            'name': admin.username,
            'title': xstr(admin.first_name) + " " + xstr(admin.last_name),
            'setType': 1,
            'users': [admin]
        }
        individualSet = UserSet(**attrs)
        self.sql_session.add(individualSet)

        self.sql_session.commit() 

    def get_submission_results(self, user, submission, task):
        result = {
            "status": None,
            "max_score": None,
            "score": None,
            "percent": None,
        }
        
        if submission is None:
            result["status"] = "none"
        else:
            sr = submission.get_result(task.active_dataset)
            score_type = get_score_type(dataset=task.active_dataset)

            if sr is None or not sr.compiled():
                result['status'] = "compiling"
            elif sr.compilation_failed():
                result['status'] = "failed_compilation"
            elif not sr.evaluated():
                result['status'] = "evaluating"
            elif not sr.scored():
                result['status'] = "scoring"
            else:
                result['status'] = "ready"

                if score_type is not None and score_type.max_score != 0:
                    result['max_score'] = round(score_type.max_score, task.score_precision)
                else:
                    result['max_score'] = 0
                result['score'] = round(sr.score, task.score_precision)
                result['percent'] = round(result['score'] * 100.0 / result['max_score'])

        return result
        
    def get_task_results(self, user, task):
        submission = self.sql_session.query(Submission)\
            .filter(Submission.user == user)\
            .filter(Submission.task == task)\
            .order_by(Submission.timestamp.desc()).first()

        return self.get_submission_results(user, submission, task)      

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
                logger.exception(error)
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

        if user.verification_type == 2:
            self.clear_cookie("login")
            self.redirect("/confirm_email/%s" % user.id)

        user.verification_type = 0

        return user

    def write_error(self, status_code, **kwargs):
        """Handles any error raised by the handler.

        """

        params = self.render_params()
        params["status_code"] = status_code
        self.render("error_page.html", **params)

    def render_params(self):
        """Return the default render params used by almost all handlers.

        return (dict): default render params

        """
        params = {}
        params["timestamp"] = make_datetime()
        params["url_root"] = get_url_root(self.request.path)
        params["current_user"] = self.current_user
        params["all_users"] = self.all_users
        params["active_sidebar_item"] = ""
        params["error"] = self.get_argument("error", "")
        params["contest_url"] = "http://%s:%s" % (self.request.host.split(':')[0], config.contest_listen_port[0]) 
        params["admin_url"] = "http://%s:%s" % (self.request.host.split(':')[0], config.admin_listen_port)
        return params

    def get_task_by_id(self, task_id):
        if not task_id.isdigit():
            raise KeyError

        for task in self.contest.tasks:
            if task.id == int(task_id):
                return task
        raise KeyError


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
    
    get_datetime = argument_reader(parse_datetime)

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

    def check_edit_user_valid_input(self, attrs):
        assert attrs.get("username") is not None,\
            "No username specified."
        name_len = len(attrs["username"])
        assert name_len >= 4 and name_len <= 24,\
            "Username must be between 4 and 24 chars."
        assert re.match(r'^[\w-]+$', attrs["username"]),\
            "Username can only contain alphanumeric characters and dashes."

        assert attrs.get("password") is not None,\
            "No password specified."
        pass_len = len(attrs["password"])
        assert pass_len >= 8 and pass_len <= 64,\
            "Password must be between 8 and 64 chars."
        
        # assert re.match(r'^[\w-@.]+$', attrs["email"]),\
        #     "Email can only contain alphanumeric characters, @, dots and dashes."
        result = email.utils.parseaddr(attrs["email"])
        assert result[0] != "" or result[1] != "",\
            "Invalid email."        

        fname_len = len(attrs["first_name"])
        assert fname_len < 56,\
            "First name must be below 56 chars."

        lname_len = len(attrs["last_name"])
        assert lname_len < 56,\
            "Last name must be below 56 chars."

    def check_signup_valid_input(self, attrs):
        self.check_edit_user_valid_input(attrs)

        num_users = self.sql_session.query(User).\
                    filter(User.username == attrs["username"]).\
                    filter(User.contest == self.contest).count()
        assert num_users < 1,\
            "Username already exists."

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
        
        ranking_enabled = len(config.rankings) > 0
        self.proxy_service = self.connect_to(
            ServiceCoord("ProxyService", 0),
            must_be_present=ranking_enabled)

        self.file_cacher = FileCacher(self)


class MainHandler(BaseHandler):
    """Home page handler

    """
    @tornado.web.authenticated
    def get(self):
        statuses = dict()
        try:
            for problemset in self.current_user.pinnedSets:
                for task in problemset.tasks:
                    statuses[task.id] = self.get_task_results(self.current_user, task)
        except KeyError:
            raise tornado.web.HTTPError(404) 

        self.r_params["sets"] = self.current_user.pinnedSets
        self.r_params["statuses"] = statuses
        self.r_params["active_sidebar_item"] = "home"
        self.render("home.html", **self.r_params)

class ProblemListHandler(BaseHandler):
    """Problem list handler

    """
    @tornado.web.authenticated
    def get(self):
        accessibleSets = set()
        for userset in self.current_user.userSets:
            for problemset in userset.problemSets:
                accessibleSets.add(problemset)

        accessibleSets = [problemset for problemset in accessibleSets]
        accessibleSets.sort(key=lambda problemset: problemset.title.lower())
        
        statuses = dict()
        try:
            for problemset in accessibleSets:
                for task in problemset.tasks:
                    statuses[task.id] = self.get_task_results(self.current_user, task)
        except KeyError:
            raise tornado.web.HTTPError(404)        

        self.r_params["sets"] = accessibleSets
        self.r_params["statuses"] = statuses
        self.r_params["active_sidebar_item"] = "problems"
        self.render("contestant_problemlist.html", **self.r_params)

class LoginHandler(BaseHandler):
    """Login handler.

    """
    def get(self):
        self.render("login.html", **self.r_params)

    def post(self):
        username = self.get_argument("username", "")
        password = self.get_argument("password", "")
        next_page = self.get_argument("next", "/")
        user = self.sql_session.query(User)\
            .filter(User.contest == self.contest)\
            .filter(User.username == username).first()

        if user is None:
            self.redirect("/login?error=Invalid username or password&ext=%s" % next_page)
            return

        if user.password != password:
            self.redirect("/login?error=Invalid username or password&next=%s" % next_page)
            return

        self.set_secure_cookie("login",
                               pickle.dumps((user.username,
                                             user.password,
                                             make_timestamp())),
                               expires_days=None)
        self.redirect(next_page)

class SignupHandler(BaseHandler):
    """Signup handler.

    """
    def get(self):
        self.render("signup.html", **self.r_params)

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
            attrs["verification_type"] = 2
            # Generate a new random verification code
            attrs["verification"] = ''.join(random.choice(string.ascii_uppercase + 
                                       string.digits) for _ in range(40))


            user = User(**attrs)
            self.sql_session.add(user)

            # Add the user to the all users group
            self.all_users.users.append(user)            

            # Add the user to its own unique userset
            attrs = {
                'name': user.username,
                'title': xstr(user.first_name) + " " + xstr(user.last_name),
                'setType': 1,
                'users': [user]
            }
            individualSet = UserSet(**attrs)
            self.sql_session.add(individualSet)

            # Add any default pinned problem sets
            accessibleSets = set()
            for userset in user.userSets:
                for problemset in userset.problemSets:
                    accessibleSets.add(problemset)

            for problem_set in accessibleSets:
                if problem_set.pinned_by_default:
                    user.pinnedSets.append(problem_set)

            self.sql_session.commit()

        except Exception as error:
            logger.exception(error)
            self.redirect("/signup?error=%s&signup=T" % error)
            return

        # Send the email
        message = ("To confirm your email please use the following verification code:\n" +
                   "%s\n" +
                   "If you did not request a new password ignore this email " +
                   "and contact an admin.\n") % user.verification

        msg = MIMEText(message)
        msg['Subject'] = "Holly email confirmation"
        msg['To'] = user.email

        send_mail(msg)

        self.redirect("/confirm_email/%s" % user.id)

class LogoutHandler(BaseHandler):
    """Logout handler.

    """
    def get(self):
        self.clear_cookie("login")
        self.redirect("/")

class AdminProblemsHandler(BaseHandler):
    """Admin Problem page handler
    
    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params = self.render_params()
        self.r_params["active_sidebar_item"] = "problems"
        self.r_params["tasks"] = self.contest.tasks
        self.render("admin_problems.html", **self.r_params)

class AdminProblemSetsHandler(BaseHandler):
    """Admin Problem-Set page handler
    
    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params = self.render_params()
        self.r_params["active_sidebar_item"] = "problemsets"
        self.r_params["sets"] = self.sql_session.query(ProblemSet)
        self.render("admin_problemsets.html", **self.r_params)


class AddProblemHandler(BaseHandler):
    """Adds a new problem.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params["active_sidebar_item"] = "problems"
        self.render("add_task.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self):
        dataset = None
        task_id = None
        try:
            attrs = dict()

            self.get_string(attrs, "name", empty=None)
            self.get_string(attrs, "title")

            assert attrs.get("name") is not None, "No task name specified."

            self.get_string(attrs, "primary_statements")

            filename = "%s.%%l" % attrs["name"]
            format_ = [SubmissionFormatElement(filename)]
            attrs["submission_format"] = format_

            attrs["token_mode"] = "disabled"
            attrs["score_precision"] = 0

            #TODO: CHANGE AFTER DEMO
            random.seed()
            attrs["num"] = random.randint(1,1000000000)
            attrs["contest"] = self.contest
            task = Task(**attrs)
            self.sql_session.add(task)
            task_id = task.id
        except Exception as error:
            self.redirect("/admin/problem/add")
            logger.exception(error)
            return

        try:
            attrs = dict()

            self.get_time_limit(attrs, "time_limit")
            self.get_memory_limit(attrs, "memory_limit")
            self.get_task_type(attrs, "task_type", "TaskTypeOptions_")

            # Create its first dataset.
            attrs["description"] = "Default"
            attrs["autojudge"] = True
            attrs["task"] = task
            attrs["score_type"] = "Sum"
            attrs["score_type_parameters"] = "1"
            dataset = Dataset(**attrs)
            self.sql_session.add(dataset)

        except Exception as error:
            logger.exception(error)
            self.redirect("/admin/problem/add")
            return

        numTests = int(self.get_argument("num_tests"))
        for i in range(0, numTests):
            
            attrs.get("new-codename-" + str(i)) is not None, logger.warning("No test name specified for %dth entry" % i)
            codename = self.get_argument("new-codename-" + str(i))
            
            try:
                input_ = self.request.files["new-input-" + str(i)][0]
                output = self.request.files["new-output-" + str(i)][0]
            except KeyError:
                logger.exception("Couldn't find files for %dth entry" % i)
                self.redirect("/admin/problem/add")
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
            except Exception as error:
                logger.exception(error)
                self.redirect("/admin/problem/add" % task_id)
                return

        try:
            # Make the dataset active. Life works better that way.
            task.active_dataset = dataset
            self.sql_session.commit()

        except Exception as error:
            logger.exception(error)
            self.redirect("/admin/problem/add")
            return

        self.redirect("/admin/problem/%s" % task.id)

class ProblemHandler(BaseHandler):
    """Shows the data of a task.

    """

    @tornado.web.authenticated
    def get(self, set_id, task_id):
        try:
            task = self.get_task_by_id(task_id)
            problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.id == set_id).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.r_params["active_sidebar_item"] = "problems"
        self.r_params["task"] = task
        self.r_params["problemset"] = problemset
        self.render("task_description.html", **self.r_params)

class AdminProblemHandler(BaseHandler):
    """Shows the data of a task.

    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self, task_id):
        inputs = dict()
        outputs = dict()
        tests_passed = dict()
        submission_stats = dict()
        user_submission_stats = dict()

        try:
            task = self.get_task_by_id(task_id)
            score_type = get_score_type(dataset=task.active_dataset)

            users = self.sql_session.query(User)\
                   .filter(User.contest == self.contest)
                   
            total_submissions = self.sql_session.query(Submission)\
                         .filter(Submission.task == task)\
                         .order_by(Submission.timestamp.desc())
        except KeyError:
            raise tornado.web.HTTPError(404)

        num_submissions = int(total_submissions.count())
        total_tests = int(score_type.max_score)

        for testcase in task.active_dataset.testcases.itervalues():
            tests_passed[testcase.codename] = 0

        # get user table data
        for user in users:
            user_submission_stats[user.username] = dict()
            
            submission = total_submissions.filter(Submission.user == user).first()
            status = self.get_submission_results(user, submission, task)

            user_submission_stats[user.username]["status"] = status["status"]

            if submission is not None:
                user_submission_stats[user.username]["percent"] = int(status["percent"])

                for result in submission.results:
                    score_details = json.loads(result.score_details)

                    num_user_tests_passed = 0
    
                    for idx,score_detail in enumerate(score_details):
                        if str(score_detail['outcome']) == "Correct":
                            num_user_tests_passed += 1

                user_submission_stats[user.username]["tests_passed"] = str(num_user_tests_passed)+"/"+str(total_tests)
                user_submission_stats[user.username]["num_submissions"] = int(total_submissions.filter(Submission.user == user).count())
            else:
                user_submission_stats[user.username]["percent"] = 0
                user_submission_stats[user.username]["tests_passed"] = "0"
                user_submission_stats[user.username]["num_submissions"] = 0

        data1 = [0]*total_tests
        data2 = [num_submissions]*total_tests
        labels = [""]*total_tests

        # get test table and graph data
        for user in users:
            for submission in total_submissions.filter(Submission.user == user):
                result = self.get_submission_results(user, submission, task)
                    
                for result in submission.results:
                    score_details = json.loads(result.score_details)
    
                    for idx,score_detail in enumerate(score_details):
                        if str(score_detail['outcome']) == "Correct":
                            tests_passed[score_detail['idx']] += 1
                            data1[idx] = tests_passed[score_detail['idx']]
                        labels[idx] = tornado.escape.utf8(str(score_detail['idx']))

        submission_stats["num_submissions"] = num_submissions
        submission_stats["tests_passed"] = tests_passed

        for testcase in task.active_dataset.testcases.itervalues():
            inputs[testcase.codename] = self.application.service.file_cacher.get_file_content(testcase.input)
            outputs[testcase.codename] = self.application.service.file_cacher.get_file_content(testcase.output)

        self.r_params["users"] = users
        self.r_params["user_submission_stats"] = user_submission_stats
        self.r_params["inputs"] = inputs
        self.r_params["active_sidebar_item"] = "problems"
        self.r_params["inputs"] = inputs
        self.r_params["outputs"] = outputs
        self.r_params["submission_stats"] = submission_stats

        self.r_params["graph_data1"] = data1
        self.r_params["graph_data2"] = data2
        self.r_params["labels"] = labels

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

        self.redirect("/admin/problems")

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

        self.r_params["active_sidebar_item"] = "problems"
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

            # save input to task
            task.name = attrs.get("name")
            task.title = attrs.get("title")
            task.primary_statements = attrs.get("primary_statements")
            task.active_dataset.time_limit = attrs.get("time_limit")
            task.active_dataset.memory_limit = attrs.get("memory_limit")
            task.active_dataset.task_type = attrs.get("task_type")
            task.active_dataset.score_type = "Sum"
            task.active_dataset.score_type_parameters = "1"

        except Exception as error:
            self.redirect("/admin/problem/%s/edit" % task_id)
            logger.exception(error)
            return


        #Add New Tests
        numTests = int(self.get_argument("num_tests"))
        logger.info("Found %d tests to add" % numTests)
        for i in range(0, numTests):
            
            attrs.get("new-codename-" + str(i)) is not None, logger.warning("No test name specified for %dth entry" % i)
            codename = self.get_argument("new-codename-" + str(i))

            logger.info("Adding testcase: %s" % codename)
            try:
                input_ = self.request.files["new-input-" + str(i)][0]
                output = self.request.files["new-output-" + str(i)][0]
            except KeyError:
                logger.exception("Couldn't find files for %dth entry" % i)
                self.redirect("/admin/problem/%s/edit" % task_id)
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
                logger.info("Adding input digest: %s" % input_digest)
                logger.info("Adding output digest: %s" % output_digest)
                testcase = Testcase(codename, public, input_digest,
                                        output_digest, dataset=task.active_dataset)
                self.sql_session.add(testcase)
            except Exception as error:
                logger.exception(error)
                self.redirect("/admin/problem/%s/edit" % task_id)
                return

        #Delete old tests
        working = dict()
        self.get_string(working, "delete_ids")
        deleteids = working["delete_ids"].strip().split()

        assert reduce(lambda x, y: x and y.isdigit(), deleteids, True), "Not all problem ids are integers"

        deleteids = map(int, deleteids)

        ## TODO: Ensure all problem ids are actually problems.

        for index, deleteid in enumerate(deleteids):
            test = self.sql_session.query(Testcase).\
               filter(Testcase.id == deleteid).one()
            try:
                self.sql_session.delete(test)
            except Exception as error:
                logger.exception(error)
                self.redirect("/admin/problem/%s/edit" % task_id)
                return

        try:
            self.sql_session.commit()
        except Exception as error:
            self.redirect("/admin/problem/%s/edit" % task_id)
            logger.exception(error)
            return

        self.redirect("/admin/problem/%s" % task_id)

class DeleteTestHandler(BaseHandler):
    """Delete a testcase.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def post(self, task_id, test_id):
        test = self.sql_session.query(Testcase).\
               filter(Testcase.id == test_id).one()
        try:
            self.sql_session.delete(test)
            self.sql_session.commit()
        except Exception as error:
            logger.exception(error)
            self.redirect("/admin/problem/%s" % task_id)
            return

        self.redirect("/admin/problem/%s" % task_id)

class SubmitHandler(BaseHandler):
    """Handles the received submissions.

    """
    @tornado.web.authenticated
    def post(self, set_id, task_id):
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
            self.r_params["message"] = "Multiple files with the same name";
            self.set_status(400)
            self.render("return_message.html", **self.r_params)
            return

        # This ensure that the user sent one file for every name in
        # submission format and no more. Less is acceptable if task
        # type says so.
        task_type = get_task_type(dataset=task.active_dataset)
        required = set([sfe.filename for sfe in task.submission_format])
        provided = set(self.request.files.keys())
        if not (required == provided or (task_type.ALLOW_PARTIAL_SUBMISSION
                                         and required.issuperset(provided))):
            self.r_params["message"] = "More than one file for every name."; 
            self.set_status(400)
            self.render("return_message.html", **self.r_params)
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
            error = "Incorrect language extension"
            self.r_params["message"] = "Incorrect language extension"; 
            self.set_status(400)
            self.render("return_message.html", **self.r_params)
            return

        # Check if submitted files are small enough.
        if any([len(f[1]) > config.max_submission_length
                for f in files.values()]):
            self.r_params["message"] = "Files are too big";
            self.set_status(400)
            self.render("return_message.html", **self.r_params)
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
            self.r_params["message"] = submission.id
            self.set_status(400)
            self.render("return_message.html", **self.r_params)
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

        self.r_params["message"] = submission.id; 
        self.render("return_message.html", **self.r_params)

class SubmissionStatusHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self, submission_id):
        submission = self.sql_session.query(Submission).filter(Submission.id == submission_id).one()
        task = submission.task

        self.r_params["result"] = submission.results[0]
        self.r_params["s"] = self.get_submission_results(self.current_user, submission, task)
        self.render("submit_status.html", **self.r_params)


class SubmissionsHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, set_id, task_id):
        try:
            task = self.get_task_by_id(task_id)
            problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.id == set_id).one()
            score_type = get_score_type(dataset=task.active_dataset)
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.r_params["submissions"] = self.sql_session.query(Submission)\
                                      .filter(Submission.task == task)\
                                      .filter(Submission.user == self.current_user)\
                                      .order_by(Submission.timestamp.desc())
        self.r_params["task"] = task
        self.r_params["score_type"] = score_type
        self.r_params["problemset"] = problemset
        self.r_params["active_sidebar_item"] = "problems"

        self.render("task_submissions.html", **self.r_params)

class ProblemSetHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, set_id):
        problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.id == set_id).one()
        statuses = dict()
        try:
            for task in problemset.tasks:
                statuses[task.id] = self.get_task_results(self.current_user, task)
        except KeyError:
            raise tornado.web.HTTPError(404)  

        self.r_params = self.render_params()
        self.r_params["problemset"] = problemset
        self.r_params["statuses"] = statuses
        self.r_params["tasks"] = [(task, self.get_task_results(self.current_user, task)) for task in problemset.tasks]
        self.r_params["active_sidebar_item"] = "problems"
        self.render("problemset.html", **self.r_params)

class ProblemSetPinHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self, set_id, action, unused):
        problem_set = self.sql_session.query(ProblemSet).filter(ProblemSet.id == set_id).one()
        if action == "unpin":
            if problem_set in self.current_user.pinnedSets:
                self.current_user.pinnedSets.remove(problem_set)

        elif action == "pin":
            self.current_user.pinnedSets.append(problem_set)

        self.sql_session.commit()

class AddProblemSetHandler(BaseHandler):
    """Adds a new problem set.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        tasks = self.sql_session.query(Task.id, Task.title).all()
        self.r_params['taskdata'] = tasks
        self.r_params["active_sidebar_item"] = "problemsets"
        self.render("add_problemset.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self):
        try:
            attrs = dict()

            self.get_string(attrs, "name", empty=None)
            self.get_string(attrs, "title")
            self.get_string(attrs, "description")
            self.get_string(attrs, "num")
            self.get_string(attrs, "pinned_by_default", empty=False)
            attrs["contest"] = self.contest

            public = self.get_argument("public", default=None)

            if "pinned_by_default" in attrs:
                attrs["pinned_by_default"] = True
            else:
                attrs["pinned_by_default"] = False

            #attrs["contest_id"] = self.contest.id
            #TODO: CHANGE AFTER DEMO
            random.seed()
            attrs["num"] = random.randint(1,1000000000)
            assert attrs.get("name") is not None, "No set name specified."

            problemset = ProblemSet(**attrs)
            self.sql_session.add(problemset)

            if public:
                self.all_users.problemSets.append(problemset)

            working = dict()
            self.get_string(working, "problemids")
            problemids = working["problemids"].strip().split()

            assert reduce(lambda x, y: x and y.isdigit(), problemids, True), "Not all problem ids are integers"

            problemids = map(int, problemids)

            ## TODO: Ensure all problem ids are actually problems.

            for index, problemid in enumerate(problemids):
                task = self.sql_session.query(Task).filter(Task.id==problemid).one()
                problemset.tasks.append(task)

            self.sql_session.commit()

        except:
            self.redirect("/admin/problemset/add")
            logger.exception(traceback.format_exc())
            return

        self.redirect("/admin/problemsets")

class AdminProblemSetHandler(BaseHandler):
    """Shows the data of a task.

    """


    @tornado.web.authenticated
    @admin_authenticated
    def get(self, problemset_id):
        try:
            problemset = self.sql_session.query(ProblemSet).\
                    filter(ProblemSet.id == problemset_id).one()
        except KeyError:
            raise tornado.web.HTTPError(404)
        self.r_params["problemset"] = problemset
        self.r_params["active_sidebar_item"] = "problemsets"
        self.render("admin_problemset.html", **self.r_params)

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
            logger.exception(error)
        self.redirect("/admin/problemsets")

class EditProblemSetHandler(BaseHandler):
    """Edits a problem set.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self, set_id):
        problemSet = self.sql_session.query(ProblemSet).filter(ProblemSet.id==set_id).one()

        all_tasks = self.sql_session.query(Task).all()
        unselected_tasks = filter(lambda x: x not in problemSet.tasks, all_tasks)

        self.r_params["problemset"] = problemSet
        self.r_params["selected_tasks"] = problemSet.tasks
        self.r_params["unselected_tasks"] = unselected_tasks
        self.r_params["active_sidebar_item"] = "problemsets"

        self.render("edit_problemset.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, set_id):
        set_id = int(set_id)
        try:
            problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.id==set_id).one()
        except:
            logger.exception(traceback.format_exc())
            self.redirect("/admin/problemset/%d/edit" % set_id)
        try:
            attrs = dict()
            self.get_string(attrs, "name", empty=None)
            self.get_string(attrs, "title", empty=None)
            self.get_string(attrs, "description", empty=None)
            self.get_string(attrs, "problemids", empty=None)
            self.get_string(attrs, "pinned_by_default", empty=None)

            public = self.get_argument("public", default=None)

            if attrs["name"] is not None:
                problemset.name = attrs["name"]

            if attrs["title"] is not None:
                problemset.title = attrs["title"]

            if attrs["description"] is not None:
                problemset.description = attrs["description"]

            if public and "pinned_by_default" in attrs:
                problemset.pinned_by_default = True
            else:
                problemset.pinned_by_default = False

            problemset.tasks = []
            if attrs["problemids"] is not None:
                problemids = attrs["problemids"].strip().split()

                assert reduce(lambda x, y: x and y.isdigit(), problemids, True), "Not all problem ids are integers"

                problemids = map(int, problemids)

                for index, problemid in enumerate(problemids):
                    task = self.sql_session.query(Task).filter(Task.id==problemid).one()
                    problemset.tasks.append(task)

            # If necessary add or remove this userSet from the allUsers group
            if public and problemset not in self.all_users.problemSets:
                self.all_users.problemSets.append(problemset)
            if not public and problemset in self.all_users.problemSets:
                self.all_users.problemSets.remove(problemset)

            self.sql_session.commit()

        except:
            logger.exception(traceback.format_exc())
            self.redirect("/admin/problemset/%d/edit" % set_id)

        self.redirect("/admin/problemsets")

class AdminUserHandler(BaseHandler):
    """Admin Users page handler
    
    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params = self.render_params()
        self.r_params["specialSets"] = self.sql_session.query(UserSet).filter(UserSet.setType==2)
        self.r_params["sets"] = self.sql_session.query(UserSet).filter(UserSet.setType==0)
        self.r_params["users"] = self.sql_session.query(User).filter(User.contest == self.contest)
        self.r_params["active_sidebar_item"] = "users"
        self.render("admin_users.html", **self.r_params)

class UserHandler(BaseHandler):
    """Shows the data of a user.

    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self, user_id):
        try:
            user = self.sql_session.query(User).\
                   filter(User.id == user_id).\
                   filter(User.contest == self.contest).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.r_params["active_sidebar_item"] = "users"
        self.render("user_description.html",
                    user=user, **self.r_params)

class EditUserHandler(BaseHandler):
    """Edits a task.
    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self, user_id):
        try:
            user = self.sql_session.query(User).\
                   filter(User.id == user_id).\
                   filter(User.contest == self.contest).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        self.r_params["active_sidebar_item"] = "users"
        self.render("edit_user.html", 
                    user=user, **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, user_id):
        try:
            user = self.sql_session.query(User).\
                   filter(User.id == user_id).\
                   filter(User.contest == self.contest).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        try:
            attrs = dict()

            # get input
            self.get_string(attrs, "first_name")
            self.get_string(attrs, "last_name")
            self.get_string(attrs, "username", empty=None)
            self.get_string(attrs, "password", empty=user.password)
            self.get_string(attrs, "email")
            
            is_admin_choice = self.get_argument("is_admin", False)

            self.check_edit_user_valid_input(attrs)

            # save input to user
            user.first_name = attrs.get("first_name")
            user.last_name = attrs.get("last_name")
            user.username = attrs.get("username")
            user.password = attrs.get("password")
            user.email = attrs.get("email")

            if user.is_training_admin and not is_admin_choice and self.sql_session.query(User)\
                    .filter(User.contest == self.contest,
                            User.is_training_admin == True).count() == 1:
                # Can't delete the last admin...
                self.redirect("/admin/users?error=You cannot stop being an administrator because you are the only administrator.") # TODO inform user
            else:
                user.is_training_admin = is_admin_choice

            self.sql_session.commit()

        except Exception as error:
            self.redirect("/admin/user/%s/edit" % user_id)
            logger.exception(error)
            return

        self.redirect("/admin/users")

class DeleteAccountHandler(BaseHandler):
    """Deletes the current user's account.

    """

    @tornado.web.authenticated
    def post(self):
        if self.current_user.is_training_admin and self.sql_session.query(User)\
            .filter(User.contest == self.contest,
                    User.is_training_admin == True).count() == 1:
            # Can't delete the last admin...
            self.redirect("/admin/problems?error=You cannot delete your account because you are the only administrator.") # TODO inform user
        else:
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
            user = self.sql_session.query(User)\
            .filter(User.id==user_id)\
            .filter(User.contest == self.contest).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        if user.is_training_admin and self.sql_session.query(User)\
            .filter(User.contest == self.contest,
                    User.is_training_admin == True).count() == 1:
            # Can't delete the last admin...
            self.redirect("/admin/users?error=You cannot delete your account because you are the only administrator.") # TODO inform user
        else:
            self.sql_session.delete(user)
            self.sql_session.commit()
            self.redirect("/admin/users")


class AdminUserSubmissionsHandler(BaseHandler):
    """Shows the history of user submissions to a problem

    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self, user_id, task_id):
        try:
            user = self.sql_session.query(User).filter(User.id==user_id)\
                       .filter(User.contest == self.contest).one()        
            task = self.get_task_by_id(task_id)

            print("user.username "+str(user.username))
            print("task.title "+str(task.title))

            # submissions = self.sql_session.query(Submission)\
                         # .filter(Submission.user == user)\
                         # .order_by(Submission.timestamp.desc())

            submissions = self.sql_session.query(Submission)\
                         .filter(Submission.user == user)\
                         .order_by(Submission.timestamp.desc())
        except KeyError:
            raise tornado.web.HTTPError(404)

        # inputs = dict()
        # outputs = dict()

        # for idx,submission in enumerate(submissions):
        #     inputs[idx] = dict()
        #     outputs[idx] = dict()
        #     dataset = submission.get_result().executables[task.title].dataset
        #     for testcase in dataset.testcases.itervalues():
        #         inputs[idx][testcase.codename] = self.application.service.file_cacher.get_file_content(testcase.input)
        #         outputs[idx][testcase.codename] = self.application.service.file_cacher.get_file_content(testcase.output)
        #         print("inputs["+str(idx)+"][testcase.codename] "+str(inputs[idx][testcase.codename]))
        #         print("outputs["+str(idx)+"][testcase.codename] "+str(outputs[idx][testcase.codename]))

        # self.r_params["inputs"] = inputs
        # self.r_params["outputs"] = outputs
        
        self.r_params["active_sidebar_item"] = "users"
        self.render("admin_user_submissions.html", 
                     user=user, task=task, **self.r_params)

class AdminUserSetHandler(BaseHandler):
    """Shows the data of a task.

    """


    @tornado.web.authenticated
    @admin_authenticated
    def get(self, userset_id):
        try:
            userset = self.sql_session.query(UserSet).\
                    filter(UserSet.id == userset_id).one()
        except KeyError:
            raise tornado.web.HTTPError(404)
        self.r_params["userset"] = userset
        self.r_params["active_sidebar_item"] = "users"
        self.render("admin_userset.html", **self.r_params)

class AddUserSetHandler(BaseHandler):
    """Adds a new user set.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params["users"] = self.sql_session.query(User).filter(User.contest == self.contest)
        self.r_params["problem_sets"] = self.sql_session.query(ProblemSet)
        self.r_params["active_sidebar_item"] = "users"
        self.render("add_userset.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self):
        try:
            attrs = {
                'setType': 0,
            }

            self.get_string(attrs, "name", empty=None)
            assert attrs.get("name") is not None, "No set name specified."
            self.get_string(attrs, "title")

            userset = UserSet(**attrs)
            self.sql_session.add(userset)

            working = dict()
            self.get_string(working, "problemsetids")
            problemsetids = working["problemsetids"].strip().split()

            assert reduce(lambda x, y: x and y.isdigit(), problemsetids, True), "Not all problem ids are integers"

            problemsetids = map(int, problemsetids)

            ## TODO: Ensure all problem ids are actually problems.

            for index, problemsetid in enumerate(problemsetids):
                problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.id==problemsetid).one()
                userset.problemSets.append(problemset)


            working = dict()
            self.get_string(working, "userids")
            userids = working["userids"].strip().split()

            assert reduce(lambda x, y: x and y.isdigit(), userids, True), "Not all problem ids are integers"

            userids = map(int, userids)

            ## TODO: Ensure all problem ids are actually problems.

            for index, userid in enumerate(userids):
                user = self.sql_session.query(User).filter(User.id==userid)\
                        .filter(User.contest == self.contest).one()
                userset.users.append(user)


            self.sql_session.commit()

        except Exception as error:
            self.redirect("/admin/userset/add")
            logger.exception(error)
            return

        self.redirect("/admin/users")

class EditUserSetHandler(BaseHandler):
    """Adds a new user set.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def get(self, userset_id):
        userset = self.sql_session.query(UserSet).filter(UserSet.id==userset_id).one()

        all_sets = self.sql_session.query(ProblemSet).all()
        unselected_sets = filter(lambda x: x not in userset.problemSets, all_sets)

        all_users = self.sql_session.query(User).filter(User.contest == self.contest).all()
        unselected_users = filter(lambda x: x not in userset.users, all_users)

        self.r_params["userset"] = userset
        self.r_params["unselected_sets"] = unselected_sets
        self.r_params["selected_sets"] = userset.problemSets
        self.r_params["unselected_users"] = unselected_users
        self.r_params["selected_users"] = userset.users
        self.r_params["active_sidebar_item"] = "users"
        self.render("edit_userset.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self, userset_id):
        set_id = int(userset_id)
        try:
            userset = self.sql_session.query(UserSet).filter(UserSet.id==set_id).one()
        except Exception as error:
            logger.exception(error)
            self.redirect("/admin/userset/%d/edit" % set_id)
        try:
            attrs = dict()
            self.get_string(attrs, "name", empty=None)
            self.get_string(attrs, "title", empty=None)
            self.get_string(attrs, "problemsetids", empty=None)
            self.get_string(attrs, "userids", empty=None)


            if attrs["name"] is not None:
                userset.name = attrs["name"]

            if attrs["title"] is not None:
                userset.title = attrs["title"]

            userset.problemSets = []
            if attrs["problemsetids"] is not None:
                problemsetids = attrs["problemsetids"].strip().split()

                assert reduce(lambda x, y: x and y.isdigit(), problemsetids, True), "Not all problem ids are integers"

                problemsetids = map(int, problemsetids)

                ## TODO: Ensure all problem ids are actually problems.

                for index, problemsetid in enumerate(problemsetids):
                    problemset = self.sql_session.query(ProblemSet).filter(ProblemSet.id==problemsetid).one()
                    userset.problemSets.append(problemset)


            if userset.setType == 0:
                userset.users = []
                if attrs["userids"] is not None:
                    userids = attrs["userids"].strip().split()

                    assert reduce(lambda x, y: x and y.isdigit(), userids, True), "Not all problem ids are integers"

                    userids = map(int, userids)

                    ## TODO: Ensure all problem ids are actually problems.

                    for index, userid in enumerate(userids):
                        user = self.sql_session.query(User).filter(User.id==userid)\
                                .filter(User.contest == self.contest).one()
                        userset.users.append(user)

            self.sql_session.commit()

        except Exception as error:
            self.redirect("/admin/userset/%s/edit" % userset_id)
            logger.exception(error)
            return

        self.redirect("/admin/users")

class DeleteUserSetHandler(BaseHandler):
    """Delete a testcase.

    """
    @tornado.web.authenticated
    @admin_authenticated
    def post(self, userset_id):
        userset = self.sql_session.query(UserSet).\
               filter(UserSet.id == userset_id,
                      UserSet.setType == 0).one()
        try:
            self.sql_session.delete(userset)
            self.sql_session.commit()
        except Exception as error:
            logger.exception(error)
            self.redirect("/admin/userset/%s" % userset_id)
            return

        self.redirect("/admin/users")


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
            logger.exception(error)
            self.redirect("/user")
            return

        self.redirect("/user")
        
class PasswordRecoveryHandler(BaseHandler):
    """Recovers a user's password

    """

    def get(self):
        self.render("recover_password.html", **self.r_params)
    
    def post(self):
        username = self.get_argument("username")
        user = self.sql_session.query(User).\
               filter(User.username == username).\
               filter(User.contest == self.contest).first()
                 
        # Check if the user exists
        if user is None:
            self.redirect("/recover_password?error=Invalid username")
            return

        if user.verification_type == 2:
            self.redirect("/confirm_email/%s?error=You must confirm your email" % user.id)
            return

        # Generate a new random verification code
        code = ''.join(random.choice(string.ascii_uppercase + 
                      string.digits) for _ in range(40))

        try:
            user.verification = code
            user.verification_type = 1
            self.sql_session.commit()
        except Exception as error:
            self.redirect("/recover_password?error=couldn't update code")
            return

        # Send the email
        message = ("To update your password please use the following verification code:\n" +
                     "%s\n" +
                     "If you did not request a new password ignore this email "
                     "and contact an admin.\n") % code

        msg = MIMEText(message)
        msg['Subject'] = "Holly password recovery"
        msg['To'] = user.email

        send_mail(msg)

        self.redirect("/change_password/%s" % user.id)

class PasswordChangeHandler(BaseHandler):
    """Change a user's password

    """

    def get(self, user_id):
        try:
            user = self.sql_session.query(User).\
                   filter(User.id == user_id).\
                   filter(User.contest == self.contest).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        if user.verification_type != 1:
            error = "No verification email has been sent"
            self.redirect("/recover_password?error=%s" % error)
            return

        self.render("change_password.html", **self.r_params)

    def post(self, user_id):
        try:
            user = self.sql_session.query(User).\
                   filter(User.id == user_id).\
                   filter(User.contest == self.contest).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        if user.verification_type != 1:
            error = "No verification email has been sent"
            self.redirect("/recover_password?error=%s" % error)
            return
            
        verification = self.get_argument("verification", "")
        
        if verification != user.verification:
            error = "Invalid verification code"
            self.redirect("/change_password/%s?error=%s" % (user_id, error))
            return

        try:
            password = self.get_argument("password", "")
            assert len(password) >= 8 and len(password) <= 64,\
                "Password must be between 8 and 64 chars."
            user.password = password
            user.verification_type = 0 
            self.sql_session.commit()
        except Exception as error:
            self.redirect("/change_password/%s?error=%s" % (user_id, error))
            return

        self.redirect("/login")
        
class EmailConfirmationHandler(BaseHandler):
    """Confirm a user's email

    """

    def get(self, user_id):
        try:
            user = self.sql_session.query(User).\
                   filter(User.id == user_id).\
                   filter(User.contest == self.contest).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        if user.verification_type != 2:
            error = "Email address is already verified."
            self.redirect("/login?error=%s" % error)
            return

        self.render("confirm_email.html", **self.r_params)

    def post(self, user_id):
        try:
            user = self.sql_session.query(User).\
                   filter(User.id == user_id).\
                   filter(User.contest == self.contest).one()
        except KeyError:
            raise tornado.web.HTTPError(404)

        if user.verification_type != 2:
            error = "Email address is already verified."
            self.redirect("/login?error=%s" % error)
            return
            
        verification = self.get_argument("verification", "")
        
        if verification != user.verification:
            error = "Invalid verification code"
            self.redirect("/confirm_email/%s?error=%s" % (user_id, error))
            return

        try:
            user.verification_type = 0 
            self.sql_session.commit()
        except Exception as error:
            self.redirect("/confirm_email/%s?error=%s" % (user_id, error))
            return

        self.set_secure_cookie("login",
                               pickle.dumps((user.username,
                                             user.password,
                                             make_timestamp())),
                               expires_days=None)
        self.redirect("/")

class ContestsHandler(BaseHandler):
    """Show all contests

    """

    @tornado.web.authenticated
    def get(self):
        contests = self.sql_session.query(Contest).\
                   filter(Contest.id != self.contest.id).\
                   filter(Contest.users.any(User.username == self.current_user.username)).\
                   order_by(Contest.start.asc())
        finished_contests = contests.filter(Contest.stop < self.timestamp)
        self.r_params["finished_contests"] = [(contest, user) for contest in finished_contests
                                              for user in contest.users 
                                              if user.username == self.current_user.username]
        future_contests = contests.filter(Contest.stop >= self.timestamp)           
        self.r_params["future_contests"] = [(contest, user) for contest in future_contests
                                            for user in contest.users 
                                            if user.username == self.current_user.username]
        self.render("contests.html", **self.r_params)

class AdminContestsHandler(BaseHandler):
    """Show all contests

    """

    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params["contests"] = self.sql_session.query(Contest).\
                                        filter(Contest.id != self.contest.id)           
        self.render("admin_contests.html", **self.r_params)
        
 
class AddContestHandler(BaseHandler):
    """Adds a new contest.

    """
    
    @tornado.web.authenticated
    @admin_authenticated
    def get(self):
        self.r_params = self.render_params()
        self.r_params["usersets"] = self.sql_session.query(UserSet).\
                                         filter(UserSet.setType != 1)                                      
        self.r_params["problemsets"] = self.sql_session.query(ProblemSet)
        self.render("add_contest.html", **self.r_params)

    @tornado.web.authenticated
    @admin_authenticated
    def post(self):
        try:
            attrs = dict()

            self.get_string(attrs, "name", empty=None)
            self.get_string(attrs, "description")

            assert attrs.get("name") is not None, "No contest name specified."

            attrs["allowed_localizations"] = []
            attrs["languages"] = self.get_arguments("languages", [])

            attrs["token_mode"] = "disabled"
            self.get_datetime(attrs, "start")
            self.get_datetime(attrs, "stop")
            attrs["score_precision"] = 0

            # Create the contest.
            contest = Contest(**attrs)
            self.sql_session.add(contest)

            attrs = dict()
            self.get_string(attrs, "problemsetids")
            problemsetids = attrs["problemsetids"].strip().split()

            assert reduce(lambda x, y: x and y.isdigit(), problemsetids, True), "Not all problem ids are integers"

            problemsetids = map(int, problemsetids)

            ## TODO: Ensure all problem ids are actually problems.

            added = Set()

            for problemsetid in problemsetids:
                problemset = self.sql_session.query(ProblemSet).\
                                              filter(ProblemSet.id==problemsetid).one()
                
                for task in problemset.tasks:
                    if task.name in added:
                        continue
                    else:
                        added.add(task.name)

                    attrs = dict()
                    attrs["name"] = task.name
                    attrs["title"] = task.title
                    attrs["primary_statements"] = task.primary_statements
                    attrs["submission_format"] = task.submission_format
                    attrs["token_mode"] = task.token_mode
                    attrs["score_precision"] = task.score_precision
                    #TODO: CHANGE AFTER DEMO
                    random.seed()
                    attrs["num"] = random.randint(1,1000000000)
                    attrs["contest"] = contest
                    new_task = Task(**attrs)
                    self.sql_session.add(new_task)

                    attrs = dict()
                    dataset = task.active_dataset
                    attrs["time_limit"] = dataset.time_limit
                    attrs["memory_limit"] = dataset.memory_limit
                    attrs["task_type"] = dataset.task_type
                    attrs["task_type_parameters"] = dataset.task_type_parameters
                    attrs["description"] = dataset.description 
                    attrs["autojudge"] = dataset.autojudge
                    attrs["task"] = new_task
                    attrs["score_type"] = dataset.score_type
                    attrs["score_type_parameters"] = dataset.score_type_parameters
                    new_dataset = Dataset(**attrs)
                    self.sql_session.add(new_dataset)

                    for codename, test in dataset.testcases.iteritems():
                        attrs = dict()
                        attrs["codename"] = codename
                        attrs["public"] = test.public
                        attrs["input"] = test.input
                        attrs["output"] = test.output
                        attrs["dataset"] = new_dataset 
                        new_test = Testcase(**attrs)
                        self.sql_session.add(new_test)

                    new_task.active_dataset = new_dataset

            attrs = dict()
            self.get_string(attrs, "usersetids")
            usersetids = attrs["usersetids"].strip().split()

            assert reduce(lambda x, y: x and y.isdigit(), usersetids, True), "Not all problem ids are integers"

            usersetids = map(int, usersetids)

            ## TODO: Ensure all problem ids are actually problems.

            added = Set()

            for usersetid in usersetids:
                userset = self.sql_session.query(UserSet).\
                                           filter(UserSet.id==usersetid).one()
                for user in userset.users:
                    if user.username in added:
                        continue
                    else:
                        added.add(user.username)

                    attrs = dict()
                    attrs["first_name"] = user.first_name
                    attrs["last_name"] = user.last_name
                    attrs["username"] = user.username
                    attrs["password"] = ''.join(random.choice(string.ascii_uppercase + 
                                                string.digits) for _ in range(8))
                    attrs["email"] = user.email

                    # Create the user.
                    attrs["contest"] = contest
                    attrs["verification_type"] = 0

                    new_user = User(**attrs)
                    self.sql_session.add(new_user)
                    
 
            self.sql_session.commit()
            self.application.service.proxy_service.reinitialize()
        except Exception as error:
            self.redirect("/admin/contest/add?error=%s", error)
            print(error)
            return
            
        self.redirect("/admin/contests")

class HallOfFameHandler(BaseHandler):
    """Show the users with the most problems solved on the site.

    """

    def get(self):
        self.r_params["active_sidebar_item"] = "fame"
        self.r_params["hofusers"] = self.sql_session.query(User.username)\
            .filter(User.contest == self.contest)

        scoretuples = self.sql_session.query(func.max(SubmissionResult.score), User.username, Task)\
            .join(Submission)\
            .join(User)\
            .join(Task)\
            .filter(User.contest_id == self.contest.id)\
            .filter(SubmissionResult.dataset_id == Task.active_dataset_id)\
            .group_by(User.username, Task).all()

        logger.warn(str(scoretuples))

        scoretuples = filter(lambda x: x[0] == get_score_type(dataset=x[2].active_dataset).max_score, scoretuples)

        usercountsdict = {}
        for foo, user, baz in scoretuples:
            usercountsdict[user] = usercountsdict.setdefault(user, 0) + 1

        usercounts = sorted([x[::-1] for x in usercountsdict.items()])[:-11:-1]

        self.r_params["hofusers"] = usercounts

        self.render("hall_of_fame.html", **self.r_params)

class NotFoundHandler(BaseHandler):
    def get(self):
        self.write_error(404)

    def post(self):
        self.write_error(404)

_tws_handlers = [
    (r"/", MainHandler),
    (r"/problems", ProblemListHandler),
    (r"/login", LoginHandler),
    (r"/signup", SignupHandler),
    (r"/logout", LogoutHandler),
    (r"/confirm_email/([0-9]+)", EmailConfirmationHandler),
    (r"/recover_password", PasswordRecoveryHandler),
    (r"/change_password/([0-9]+)", PasswordChangeHandler),
    (r"/hof", HallOfFameHandler),
    (r"/contests", ContestsHandler),
    (r"/problem/([0-9]+)/([0-9]+)", ProblemHandler),
    (r"/problem/([0-9]+)/([0-9]+)/submit", SubmitHandler),
    (r"/problem/([0-9]+)/([0-9]+)/submissions", SubmissionsHandler),
    (r"/problem/([0-9]+)/submission_status", SubmissionStatusHandler),
    (r"/problemset/([0-9]+)", ProblemSetHandler),
    (r"/problemset/([0-9]+)/((un)?pin)", ProblemSetPinHandler),
    (r"/user", UserInfoHandler),
    (r"/user/delete", DeleteAccountHandler),
    (r"/admin/contests", AdminContestsHandler),
    (r"/admin/contest/add", AddContestHandler),
    (r"/admin/problems", AdminProblemsHandler),
    (r"/admin/problem/([0-9]+)", AdminProblemHandler),
    (r"/admin/problem/add", AddProblemHandler),
    (r"/admin/problem/([0-9]+)/delete", DeleteProblemHandler),
    (r"/admin/problem/([0-9]+)/edit", EditProblemHandler),
    (r"/admin/problemsets", AdminProblemSetsHandler),
    (r"/admin/problemset/add", AddProblemSetHandler),
    (r"/admin/problemset/([0-9]+)/delete", DeleteProblemSetHandler),
    (r"/admin/problemset/([0-9]+)", AdminProblemSetHandler),
    (r"/admin/problemset/([0-9]+)/edit", EditProblemSetHandler),
    (r"/admin/users", AdminUserHandler),
    (r"/admin/user/([0-9]+)", UserHandler),
    (r"/admin/user/([0-9]+)/edit", EditUserHandler),
    (r"/admin/user/([0-9]+)/delete", DeleteUserHandler),
    (r"/admin/user/([0-9]+)/([0-9]+)/submissions", AdminUserSubmissionsHandler),
    (r"/admin/userset/add", AddUserSetHandler),
    (r"/admin/userset/([0-9]+)", AdminUserSetHandler),
    (r"/admin/userset/([0-9]+)/edit", EditUserSetHandler),
    (r"/admin/userset/([0-9]+)/delete", DeleteUserSetHandler),
    (r"/.*", NotFoundHandler),
]
