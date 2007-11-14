import os
from pickle import dumps, loads
from base64 import b64encode, b64decode
import copy
import logging

import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
from turbogears import identity

from ipacontroller import IPAController
from ipa.entity import utf8_encode_values
from ipa import ipaerror

import ldap.dn

log = logging.getLogger(__name__)

class PolicyController(IPAController):

    @expose("ipagui.templates.policyindex")
    @identity.require(identity.in_group("admins"))
    def index(self, tg_errors=None):
        """Displays the one policy page"""

        # TODO: return a dict of the items and URLs to display on
        #       Manage Policy
        return dict()
