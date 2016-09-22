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

import time
import re

import six
import gssapi

from ipalib import errors

if six.PY3:
    unicode = str

#-------------------------------------------------------------------------------

# Kerberos error codes
KRB5_CC_NOTFOUND                = 2529639053 # Matching credential not found
KRB5_FCC_NOFILE                 = 2529639107 # No credentials cache found
KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN = 2529638918  # client not found in Kerberos db
KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN = 2529638919 # Server not found in Kerberos database
KRB5KRB_AP_ERR_TKT_EXPIRED      = 2529638944 # Ticket expired
KRB5_FCC_PERM                   = 2529639106 # Credentials cache permissions incorrect
KRB5_CC_FORMAT                  = 2529639111 # Bad format in credentials cache
KRB5_REALM_CANT_RESOLVE         = 2529639132 # Cannot resolve network address for KDC in requested realm

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

def get_credentials(name=None, ccache_name=None):
    '''
    Obtains GSSAPI credentials with given principal name from ccache. When no
    principal name specified, it retrieves the default one for given
    credentials cache.

    :parameters:
      name
        gssapi.Name object specifying principal or None for the default
      ccache_name
        string specifying Kerberos credentials cache name or None for the
        default
    :returns:
      gssapi.Credentials object
    '''
    store = None
    if ccache_name:
        store = {'ccache': ccache_name}
    try:
        return gssapi.Credentials(usage='initiate', name=name, store=store)
    except gssapi.exceptions.GSSError as e:
        if e.min_code == KRB5_FCC_NOFILE:  # pylint: disable=no-member
            raise ValueError('"%s", ccache="%s"' % (e, ccache_name))
        raise

def get_principal(ccache_name=None):
    '''
    Gets default principal name from given credentials cache.

    :parameters:
      ccache_name
        string specifying Kerberos credentials cache name or None for the
        default
    :returns:
      Default principal name as string
    :raises:
      errors.CCacheError if the principal cannot be retrieved from given
      ccache
    '''
    try:
        creds = get_credentials(ccache_name=ccache_name)
        return unicode(creds.name)
    except gssapi.exceptions.GSSError as e:
        raise errors.CCacheError(message=unicode(e))

def get_credentials_if_valid(name=None, ccache_name=None):
    '''
    Obtains GSSAPI credentials with principal name from ccache. When no
    principal name specified, it retrieves the default one for given
    credentials cache. When the credentials cannot be retrieved or aren't valid
    it returns None.

    :parameters:
      name
        gssapi.Name object specifying principal or None for the default
      ccache_name
        string specifying Kerberos credentials cache name or None for the
        default
    :returns:
      gssapi.Credentials object or None if valid credentials weren't found
    '''

    try:
        creds = get_credentials(name=name, ccache_name=ccache_name)
        if creds.lifetime > 0:
            return creds
        return None
    except gssapi.exceptions.ExpiredCredentialsError:
        return None
    except gssapi.exceptions.GSSError:
        return None
