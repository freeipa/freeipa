# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2012  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import krbV
import time
import re
from ipapython.ipa_log_manager import *

#-------------------------------------------------------------------------------

# Kerberos constants, should be defined in krbV, but aren't
KRB5_GC_CACHED = 0x2

# Kerberos error codes, should be defined in krbV, but aren't
KRB5_CC_NOTFOUND                = -1765328243 # Matching credential not found
KRB5_FCC_NOFILE                 = -1765328189 # No credentials cache found
KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN = -1765328377 # Server not found in Kerberos database
KRB5KRB_AP_ERR_TKT_EXPIRED      = -1765328352 # Ticket expired
KRB5_FCC_PERM                   = -1765328190 # Credentials cache permissions incorrect
KRB5_CC_FORMAT                  = -1765328185 # Bad format in credentials cache
KRB5_REALM_CANT_RESOLVE         = -1765328164 # Cannot resolve network address for KDC in requested realm


krb_ticket_expiration_threshold = 60*5 # number of seconds to accmodate clock skew
krb5_time_fmt = '%m/%d/%y %H:%M:%S'
ccache_name_re = re.compile(r'^((\w+):)?(.+)')

#-------------------------------------------------------------------------------

def krb5_parse_ccache(ccache_name):
    '''
    Given a Kerberos ccache name parse it into it's scheme and
    location components. Currently valid values for the scheme
    are:

      * FILE
      * MEMORY

    The scheme is always returned as upper case. If the scheme
    does not exist it defaults to FILE.

    :parameters:
      ccache_name
        The name of the Kerberos ccache.
    :returns:
      A two-tuple of (scheme, ccache)
    '''
    match = ccache_name_re.search(ccache_name)
    if match:
        scheme = match.group(2)
        location = match.group(3)
        if scheme is None:
            scheme = 'FILE'
        else:
            scheme = scheme.upper()

        return scheme, location
    else:
        raise ValueError('Invalid ccache name = "%s"' % ccache_name)

def krb5_unparse_ccache(scheme, name):
    return '%s:%s' % (scheme.upper(), name)

def krb5_format_principal_name(user, realm):
    '''
    Given a Kerberos user principal name and a Kerberos realm
    return the Kerberos V5 user principal name.

    :parameters:
      user
        User principal name.
      realm
        The Kerberos realm the user exists in.
    :returns:
      Kerberos V5 user principal name.
    '''
    return '%s@%s' % (user, realm)

def krb5_format_service_principal_name(service, host, realm):
    '''

    Given a Kerberos service principal name, the host where the
    service is running and a Kerberos realm return the Kerberos V5
    service principal name.

    :parameters:
      service
        Service principal name.
      host
        The DNS name of the host where the service is located.
      realm
        The Kerberos realm the service exists in.
    :returns:
      Kerberos V5 service principal name.
    '''
    return '%s/%s@%s' % (service, host, realm)

def krb5_format_tgt_principal_name(realm):
    '''
    Given a Kerberos realm return the Kerberos V5 TGT name.

    :parameters:
      realm
        The Kerberos realm the TGT exists in.
    :returns:
      Kerberos V5 TGT name.
    '''
    return krb5_format_service_principal_name('krbtgt', realm, realm)

def krb5_format_time(timestamp):
    '''
    Given a UNIX timestamp format it into a string in the same
    manner the MIT Kerberos library does. Kerberos timestamps are
    always in local time.

    :parameters:
      timestamp
        Unix timestamp
    :returns:
      formated string
    '''
    return time.strftime(krb5_time_fmt, time.localtime(timestamp))

class KRB5_CCache(object):
    '''
    Kerberos stores a TGT (Ticket Granting Ticket) and the service
    tickets bound to it in a ccache (credentials cache). ccaches are
    bound to a Kerberos user principal. This class opens a Kerberos
    ccache and allows one to manipulate it. Most useful is the
    extraction of ticket entries (cred's) in the ccache and the
    ability to examine their attributes.
    '''

    def __init__(self, ccache):
        '''
        :parameters:
          ccache
            The name of a Kerberos ccache used to hold Kerberos tickets.
        :returns:
          `KRB5_CCache` object encapsulting the ccache.
        '''
        log_mgr.get_logger(self, True)
        self.context = None
        self.scheme = None
        self.name = None
        self.ccache = None
        self.principal = None

        try:
            self.context = krbV.default_context()
            self.scheme, self.name = krb5_parse_ccache(ccache)
            self.ccache = krbV.CCache(name=str(ccache), context=self.context)
            self.principal = self.ccache.principal()
        except krbV.Krb5Error, e:
            error_code = e.args[0]
            message = e.args[1]
            if error_code == KRB5_FCC_NOFILE:
                raise ValueError('"%s", ccache="%s"' % (message, ccache))
            else:
                raise e

    def ccache_str(self):
        '''
        A Kerberos ccache is identified by a name comprised of a
        scheme and location component. This function returns that
        canonical name. See `krb5_parse_ccache()`

        :returns:
          The name of ccache with it's scheme and location components.
        '''

        return '%s:%s' % (self.scheme, self.name)

    def __str__(self):
        return 'cache="%s" principal="%s"' % (self.ccache_str(), self.principal.name)

    def get_credentials(self, principal):
        '''
        Given a Kerberos principal return the krbV credentials
        tuple describing the credential. If the principal does
        not exist in the ccache a KeyError is raised.

        :parameters:
          principal
            The Kerberos principal whose ticket is being retrieved.
            The principal may be either a string formatted as a
            Kerberos V5 principal or it may be a `krbV.Principal`
            object.
        :returns:
          A krbV credentials tuple. If the principal is not in the
          ccache a KeyError is raised.

        '''

        if isinstance(principal, krbV.Principal):
            krbV_principal = principal
        else:
            try:
                krbV_principal = krbV.Principal(str(principal), self.context)
            except Exception, e:
                self.error('could not create krbV principal from "%s", %s', principal, e)
                raise e

        creds_tuple = (self.principal,
                       krbV_principal,
                       (0, None),    # keyblock: (enctype, contents)
                       (0, 0, 0, 0), # times: (authtime, starttime, endtime, renew_till)
                       0,0,          # is_skey, ticket_flags
                       None,         # addrlist
                       None,         # ticket_data
                       None,         # second_ticket_data
                       None)         # adlist
        try:
            cred = self.ccache.get_credentials(creds_tuple, KRB5_GC_CACHED)
        except krbV.Krb5Error, e:
            error_code = e.args[0]
            if error_code == KRB5_CC_NOTFOUND:
                raise KeyError('"%s" credential not found in "%s" ccache' % \
                               (krbV_principal.name, self.ccache_str())) #pylint: disable=E1103
            raise e
        except Exception, e:
            raise e

        return cred

    def get_credential_times(self, principal):
        '''
        Given a Kerberos principal return the ticket timestamps if the
        principal's ticket in the ccache is valid.  If the principal
        does not exist in the ccache a KeyError is raised.

        The return credential time values are Unix timestamps in
        localtime.

        The returned timestamps are:

        authtime
          The time when the ticket was issued.
        starttime
          The time when the ticket becomes valid.
        endtime
          The time when the ticket expires.
        renew_till
          The time when the ticket becomes no longer renewable (if renewable).

        :parameters:
          principal
            The Kerberos principal whose ticket is being validated.
            The principal may be either a string formatted as a
            Kerberos V5 principal or it may be a `krbV.Principal`
            object.
        :returns:
            return authtime, starttime, endtime, renew_till
        '''

        if isinstance(principal, krbV.Principal):
            krbV_principal = principal
        else:
            try:
                krbV_principal = krbV.Principal(str(principal), self.context)
            except Exception, e:
                self.error('could not create krbV principal from "%s", %s', principal, e)
                raise e

        try:
            cred = self.get_credentials(krbV_principal)
            authtime, starttime, endtime, renew_till = cred[3]

            self.debug('get_credential_times: principal=%s, authtime=%s, starttime=%s, endtime=%s, renew_till=%s',
                       krbV_principal.name, #pylint: disable=E1103
                       krb5_format_time(authtime), krb5_format_time(starttime),
                       krb5_format_time(endtime), krb5_format_time(renew_till))

            return authtime, starttime, endtime, renew_till

        except KeyError, e:
            raise e
        except Exception, e:
            self.error('get_credential_times failed, principal="%s" error="%s"', krbV_principal.name, e) #pylint: disable=E1103
            raise e

    def credential_is_valid(self, principal):
        '''
        Given a Kerberos principal return a boolean indicating if the
        principal's ticket in the ccache is valid. If the ticket is
        not in the ccache False is returned. If the ticket
        exists in the ccache it's validity is checked and returned.

        :parameters:
          principal
            The Kerberos principal whose ticket is being validated.
            The principal may be either a string formatted as a
            Kerberos V5 principal or it may be a `krbV.Principal`
            object.
        :returns:
          True if the principal's ticket exists and is valid. False if
          the ticket does not exist or if the ticket is not valid.
        '''

        try:
            authtime, starttime, endtime, renew_till = self.get_credential_times(principal)
        except KeyError, e:
            return False
        except Exception, e:
            self.error('credential_is_valid failed, principal="%s" error="%s"', principal, e)
            raise e


        now = time.time()
        if starttime > now:
            return False
        if endtime < now:
            return False
        return True

    def valid(self, host, realm):
        '''
        Test to see if ldap service ticket or the TGT is valid.

        :parameters:
          host
            ldap server
          realm
            kerberos realm
        :returns:
          True if either the ldap service ticket or the TGT is valid,
          False otherwise.
        '''

        try:
            principal = krb5_format_service_principal_name('HTTP', host, realm)
            valid = self.credential_is_valid(principal)
            if valid:
                return True
        except KeyError:
            pass

        try:
            principal = krb5_format_tgt_principal_name(realm)
            valid = self.credential_is_valid(principal)
            return valid
        except KeyError:
            return False

    def endtime(self, host, realm):
        '''
        Returns the minimum endtime for tickets of interest (ldap service or TGT).

        :parameters:
          host
            ldap server
          realm
            kerberos realm
        :returns:
          UNIX timestamp value.
        '''

        result = 0
        try:
            principal = krb5_format_service_principal_name('HTTP', host, realm)
            authtime, starttime, endtime, renew_till = self.get_credential_times(principal)
            if result:
                result = min(result, endtime)
            else:
                result = endtime
        except KeyError:
            pass

        try:
            principal = krb5_format_tgt_principal_name(realm)
            authtime, starttime, endtime, renew_till = self.get_credential_times(principal)
            if result:
                result = min(result, endtime)
            else:
                result = endtime
        except KeyError:
            pass

        self.debug('KRB5_CCache %s endtime=%s (%s)', self.ccache_str(), result, krb5_format_time(result))
        return result
