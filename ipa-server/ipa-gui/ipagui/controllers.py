import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
from turbogears import identity
# from model import *
# import logging
# log = logging.getLogger("ipagui.controllers")

import ipa.config
import ipa.ipaclient

from subcontrollers.user import UserController
from subcontrollers.group import GroupController
from subcontrollers.delegation import DelegationController

ipa.config.init_config()

class Root(controllers.RootController):
    user = UserController()
    group = GroupController()
    delegate = DelegationController()

    @expose(template="ipagui.templates.welcome")
    @identity.require(identity.not_anonymous())
    def index(self):
        return dict()

    @expose()
    @identity.require(identity.not_anonymous())
    def topsearch(self, **kw):
        if kw.get('searchtype') == "Users":
            return Root.user.list(uid=kw.get('searchvalue'))
        else:
            return Root.group.list(criteria=kw.get('searchvalue'))

    @expose("ipagui.templates.loginfailed")
    def loginfailed(self, **kw):
        return dict()
