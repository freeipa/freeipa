import logging
import StringIO
import traceback

import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import config
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
from turbogears import identity

import ipa.config
import ipa.ipaclient

from subcontrollers.user import UserController
from subcontrollers.group import GroupController
from subcontrollers.delegation import DelegationController
from subcontrollers.policy import PolicyController
from subcontrollers.ipapolicy import IPAPolicyController
from subcontrollers.principal import PrincipalController

ipa.config.init_config()

log = logging.getLogger(__name__)

class Root(controllers.RootController):

    user = UserController()
    group = GroupController()
    delegate = DelegationController()
    policy = PolicyController()
    ipapolicy = IPAPolicyController()
    principal = PrincipalController()

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


    _error_codes = {
        None: u'General Error',
        400: u'400 - Bad Request',
        401: u'401 - Unauthorized',
        403: u'403 - Forbidden',
        404: u'404 - Not Found',
        500: u'500 - Internal Server Error',
        501: u'501 - Not Implemented',
        502: u'502 - Bad Gateway',
    }

    def handle_error(self, status, message):
        """This method is derived from the sample error catcher on
           http://docs.turbogears.org/1.0/ErrorReporting."""
        try:
            cherrypy._cputil._cp_on_http_error(status, message)
            error_msg = self._error_codes.get(status, self._error_codes[None])
            url = "%s %s" % (cherrypy.request.method, cherrypy.request.path)
            log.exception("CherryPy %s error (%s) for request '%s'", status,
                          error_msg, url)

            if config.get('server.environment') == 'production':
                details = ''
            else:
                buf = StringIO.StringIO()
                traceback.print_exc(file=buf)
                details = buf.getvalue()
                buf.close()

            data = dict(
                status = status,
                message = message,
                error_msg = error_msg,
                url = url,
                details = details,
            )

            body = controllers._process_output(
                data,
                'ipagui.templates.unhandled_exception',
                'html',
                'text/html',
                None
            )
            cherrypy.response.headers['Content-Length'] = len(body)
            cherrypy.response.body = body

        # don't catch SystemExit
        except StandardError, exc:
            log.exception('Error handler failed: %s', exc)

    # To hook in error handler for production only:
    # if config.get('server.environment') == 'production':
    #     _cp_on_http_error = handle_error

    _cp_on_http_error = handle_error
