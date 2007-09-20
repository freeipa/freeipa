from turbogears.identity.soprovider import *
from turbogears.identity.visitor import *
import logging
import os

log = logging.getLogger("turbogears.identity")

class IPA_User(object):
    '''
    Shell of a User definition. We don't really need much here.
    '''

    def __init__(self, user_name):
        self.user_name = user_name
        self.display_name = user_name
        self.permissions = None
        self.groups = None
        return

class ProxyIdentity(object):
    def __init__(self, visit_key, user=None):
        self._user= user
        self.visit_key= visit_key
   
    def _get_user(self):
        try:
            return self._user
        except AttributeError:
            # User hasn't already been set
            return None
    user= property(_get_user)

    def _get_user_name(self):
        if not self._user:
            return None
        return self._user.user_name
    user_name= property(_get_user_name)

    def _get_display_name(self):
        if not self._user:
            return None
        return self._user.display_name
    display_name= property(_get_display_name)

    def _get_anonymous(self):
        return not self._user
    anonymous= property(_get_anonymous)

    def _get_permissions(self):
        try:
            return self._permissions
        except AttributeError:
            # Permissions haven't been computed yet
            return None
    permissions= property(_get_permissions)

    def _get_groups(self):
        try:
            return self._groups
        except AttributeError:
            # Groups haven't been computed yet
            return None
    groups= property(_get_groups)

    def logout(self):
        '''
        Remove the link between this identity and the visit.
        '''
        # Clear the current identity
        anon= ProxyObjectIdentity(None,None)
        #XXX if user is None anonymous will be true, no need to set attr.
        #anon.anonymous= True
        identity.set_current_identity( anon )

class ProxyIdentityProvider(SqlObjectIdentityProvider):
    '''
    IdentityProvider that uses REMOTE_USER from Apache
    '''
    def __init__(self):
        super(ProxyIdentityProvider, self).__init__()
        get = turbogears.config.get
        # We can get any config variables here
        log.info( "Proxy Identity starting" )

    def create_provider_model(self):
        pass

    def validate_identity(self, user_name, password, visit_key):
        user = IPA_User(user_name)
        log.debug( "validate_identity %s" % user_name)
  
        return ProxyIdentity(visit_key, user)

    def validate_password(self, user, user_name, password):
        '''Validation has already occurred in the proxy'''
        return True

    def load_identity(self, visit_key):
        try:
            user_name= cherrypy.request.headers['X-FORWARDED-USER']
            os.environ["KRB5CCNAME"] = cherrypy.request.headers['X-FORWARDED-KEYTAB']
#             user_name = "test@FREEIPA.ORG"
#             os.environ["KRB5CCNAME"] = "FILE:/tmp/krb5cc_500"
        except KeyError:
            return None
        set_login_attempted( True )
        return self.validate_identity( user_name, None, visit_key )

    def anonymous_identity( self ):
        '''
        This shouldn't ever happen in IPA but including it to include the
        entire identity API.
        '''
        return ProxyIdentity( None )

    def authenticated_identity(self, user):
        '''
        Constructs Identity object for user that has no associated visit_key.
        '''
        return ProxyIdentity(None, user)
