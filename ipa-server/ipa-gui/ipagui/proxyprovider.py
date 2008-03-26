# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

from turbogears.identity.soprovider import *
from turbogears.identity.visitor import *
import logging
import os
import ipa.ipaclient
from ipaserver import funcs
import ipa.config
import ipa.group
import ipa.user
import ldap
import krbV

log = logging.getLogger("turbogears.identity")

class IPA_User(object):
    '''
    Shell of a User definition. We don't really need much here.
    '''

    def __init__(self, user_name):
        self.user_name = user_name
        (principal, realm) = user_name.split('@')
        self.display_name = principal
        self.permissions = None
        transport = funcs.IPAServer()
        client = ipa.ipaclient.IPAClient(transport)
        client.set_krbccache(os.environ["KRB5CCNAME"])
        try:
            # Use memberof so we can see recursive group memberships as well.
            user = client.get_user_by_principal(user_name, ['dn', 'memberof'])
            self.groups = []
            memberof = user.getValues('memberof')
            if memberof is None:
                # the user isn't in any groups
                return
            if isinstance(memberof, str):
                memberof = [memberof]
            for mo in memberof:
                rdn_list = ldap.explode_dn(mo, 0)
                first_rdn = rdn_list[0]
                (type,value) = first_rdn.split('=')
                if type == "cn":
                    self.groups.append(value)
        except:
            raise

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
            return self._user.groups
        except AttributeError:
            # Groups haven't been computed yet
            return []
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
        try:
            user = IPA_User(user_name)
            log.debug( "validate_identity %s" % user_name)
            return ProxyIdentity(visit_key, user)
        except Exception, e:
            # Something went wrong in fetching the user. Set to
            # anonymous which will deny access.
            return ProxyIdentity( None )

    def validate_password(self, user, user_name, password):
        '''Validation has already occurred in the proxy'''
        return True

    def load_identity(self, visit_key):
        try:
            os.environ["KRB5CCNAME"] = cherrypy.request.headers['X-FORWARDED-KEYTAB']
            ccache = krbV.CCache(cherrypy.request.headers['X-FORWARDED-KEYTAB'])
            user_name = ccache.principal().name
#            user_name = "test@FREEIPA.ORG"
#            os.environ["KRB5CCNAME"] = "FILE:/tmp/krb5cc_500"
        except KeyError:
            return None
        except AttributeError:
            return None
        except krbV.Krb5Error:
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
