# Authors: John Dennis <jdennis@redhat.com>
#
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

import sys
import os
import re
import ldap
import ldap.filter

from ipa import ipautil


__all__ = [
    'RADIUS_PKG_NAME',
    'RADIUS_PKG_CONFIG_DIR',
    'RADIUS_SERVICE_NAME',
    'RADIUS_USER',
    'RADIUS_IPA_KEYTAB_FILEPATH',
    'RADIUS_LDAP_ATTR_MAP_FILEPATH',
    'RADIUSD_CONF_FILEPATH',
    'RADIUSD_CONF_TEMPLATE_FILEPATH',
    'RADIUSD',

    'clients_container',
    'radius_clients_basedn',
    'radius_client_filter',
    'radius_client_dn',

    'profiles_container',
    'radius_profiles_basedn',
    'radius_profile_filter',
    'radius_profile_dn',

    'radius_client_ldap_attr_to_radius_attr',
    'radius_client_attr_to_ldap_attr',

    'radius_profile_ldap_attr_to_radius_attr',
    'radius_profile_attr_to_ldap_attr',

    'read_pairs_file',
]

#------------------------------------------------------------------------------

RADIUS_PKG_NAME = 'freeradius'
RADIUS_PKG_CONFIG_DIR      = '/etc/raddb'

RADIUS_SERVICE_NAME = 'radius'
RADIUS_USER         = 'radiusd'

RADIUS_IPA_KEYTAB_FILEPATH     = os.path.join(RADIUS_PKG_CONFIG_DIR, 'ipa.keytab')
RADIUS_LDAP_ATTR_MAP_FILEPATH  = os.path.join(RADIUS_PKG_CONFIG_DIR, 'ldap.attrmap')
RADIUSD_CONF_FILEPATH          = os.path.join(RADIUS_PKG_CONFIG_DIR, 'radiusd.conf')
RADIUSD_CONF_TEMPLATE_FILEPATH = os.path.join(ipautil.SHARE_DIR,     'radius.radiusd.conf.template')

RADIUSD = '/usr/sbin/radiusd'

#------------------------------------------------------------------------------

def reverse_map_dict(src_dict):
    reverse_dict = {}

    for k,v in src_dict.items():
        if reverse_dict.has_key(v):
            raise ValueError("reverse_map_dict: collision on (%s) with values (%s),(%s)" % \
                                 v, reverse_dict[v], src_dict[k])
        reverse_dict[v] = k
    return reverse_dict

#------------------------------------------------------------------------------

radius_client_ldap_attr_to_radius_attr = ipautil.CIDict({
    'radiusClientIPAddress' : 'Client-IP-Address',
    'radiusClientSecret'    : 'Secret',
    'radiusClientNASType'   : 'NAS-Type',
    'radiusClientShortName' : 'Name',
    'description'           : 'Description',
 })

radius_client_attr_to_ldap_attr = reverse_map_dict(radius_client_ldap_attr_to_radius_attr)

#------------------------------------------------------------------------------

radius_profile_ldap_attr_to_radius_attr = {
    'radiusArapFeatures'            : 'Arap-Features',
    'radiusArapSecurity'            : 'Arap-Security',
    'radiusArapZoneAccess'          : 'Arap-Zone-Access',
    'radiusAuthType'                : 'Auth-Type',
    'radiusCallbackId'              : 'Callback-Id',
    'radiusCallbackNumber'          : 'Callback-Number',
    'radiusCalledStationId'         : 'Called-Station-Id',
    'radiusCallingStationId'        : 'Calling-Station-Id',
    'radiusClass'                   : 'Class',
    'radiusClientIPAddress'         : 'Client-IP-Address',
    'radiusExpiration'              : 'Expiration',
    'radiusFilterId'                : 'Filter-Id',
    'radiusFramedAppleTalkLink'     : 'Framed-AppleTalk-Link',
    'radiusFramedAppleTalkNetwork'  : 'Framed-AppleTalk-Network',
    'radiusFramedAppleTalkZone'     : 'Framed-AppleTalk-Zone',
    'radiusFramedCompression'       : 'Framed-Compression',
    'radiusFramedIPAddress'         : 'Framed-IP-Address',
    'radiusFramedIPNetmask'         : 'Framed-IP-Netmask',
    'radiusFramedIPXNetwork'        : 'Framed-IPX-Network',
    'radiusFramedMTU'               : 'Framed-MTU',
    'radiusFramedProtocol'          : 'Framed-Protocol',
    'radiusFramedRoute'             : 'Framed-Route',
    'radiusFramedRouting'           : 'Framed-Routing',
    'radiusGroupName'               : 'Group-Name',
    'radiusHint'                    : 'Hint',
    'radiusHuntgroupName'           : 'Huntgroup-Name',
    'radiusIdleTimeout'             : 'Idle-Timeout',
    'radiusLoginIPHost'             : 'Login-IP-Host',
    'radiusLoginLATGroup'           : 'Login-LAT-Group',
    'radiusLoginLATNode'            : 'Login-LAT-Node',
    'radiusLoginLATPort'            : 'Login-LAT-Port',
    'radiusLoginLATService'         : 'Login-LAT-Service',
    'radiusLoginService'            : 'Login-Service',
    'radiusLoginTCPPort'            : 'Login-TCP-Port',
    'radiusLoginTime'               : 'Login-Time',
    'radiusNASIpAddress'            : 'NAS-IP-Address',
    'radiusPasswordRetry'           : 'Password-Retry',
    'radiusPortLimit'               : 'Port-Limit',
    'radiusProfileDn'               : 'Profile-Dn',
    'radiusPrompt'                  : 'Prompt',
    'radiusProxyToRealm'            : 'Proxy-To-Realm',
    'radiusRealm'                   : 'Realm',
    'radiusReplicateToRealm'        : 'Replicate-To-Realm',
    'radiusReplyMessage'            : 'Reply-Message',
    'radiusServiceType'             : 'Service-Type',
    'radiusSessionTimeout'          : 'Session-Timeout',
    'radiusSimultaneousUse'         : 'Simultaneous-Use',
    'radiusStripUserName'           : 'Strip-User-Name',
    'radiusTerminationAction'       : 'Termination-Action',
    'radiusTunnelAssignmentId'      : 'Tunnel-Assignment-Id',
    'radiusTunnelClientEndpoint'    : 'Tunnel-Client-Endpoint',
    'radiusTunnelMediumType'        : 'Tunnel-Medium-Type',
    'radiusTunnelPassword'          : 'Tunnel-Password',
    'radiusTunnelPreference'        : 'Tunnel-Preference',
    'radiusTunnelPrivateGroupId'    : 'Tunnel-Private-Group-Id',
    'radiusTunnelServerEndpoint'    : 'Tunnel-Server-Endpoint',
    'radiusTunnelType'              : 'Tunnel-Type',
    'radiusUserCategory'            : 'User-Category',
    'radiusVSA'                     : 'VSA',
}

radius_profile_attr_to_ldap_attr = reverse_map_dict(radius_profile_ldap_attr_to_radius_attr)

#------------------------------------------------------------------------------

clients_container = 'cn=clients,cn=radius,cn=services,cn=etc'

def radius_clients_basedn(container, suffix):
    if container is None: container = clients_container
    return '%s,%s' % (container, suffix)

def radius_client_filter(ip_addr):
    return "(&(radiusClientIPAddress=%s)(objectclass=radiusClientProfile))" %  \
        ldap.filter.escape_filter_chars(ip_addr)

def radius_client_dn(client, container, suffix):
    if container is None: container = clients_container
    return 'radiusClientIPAddress=%s,%s,%s' % (ldap.dn.escape_dn_chars(client), container, suffix)

# --

profiles_container = 'cn=profiles,cn=radius,cn=services,cn=etc'

def radius_profiles_basedn(container, suffix):
    if container is None: container = profiles_container
    return '%s,%s' % (container, suffix)

def radius_profile_filter(uid):
    return "(&(uid=%s)(objectclass=radiusprofile))" %  \
        ldap.filter.escape_filter_chars(uid)

def radius_profile_dn(uid, container, suffix):
    if container is None: container = profiles_container
    return 'uid=%s,%s,%s' % (ldap.dn.escape_dn_chars(uid), container, suffix)


#------------------------------------------------------------------------------

comment_re = re.compile('#.*$', re.MULTILINE)
def read_pairs_file(filename):
    if filename == '-':
        fd = sys.stdin
    else:
        fd = open(filename)
    data = fd.read()
    data = comment_re.sub('', data) # kill comments
    pairs = ipautil.parse_key_value_pairs(data)
    if fd != sys.stdin: fd.close()
    return pairs


def get_ldap_attr_translations():
    comment_re = re.compile('#.*$')
    radius_attr_to_ldap_attr = {}
    ldap_attr_to_radius_attr = {}
    try:
        f = open(LDAP_ATTR_MAP_FILEPATH)
        for line in f.readlines():
            line = comment_re.sub('', line).strip()
            if not line: continue
            attr_type, radius_attr, ldap_attr = line.split()
            print 'type="%s" radius="%s" ldap="%s"' % (attr_type, radius_attr, ldap_attr)
            radius_attr_to_ldap_attr[radius_attr] = {'ldap_attr':ldap_attr, 'attr_type':attr_type}
            ldap_attr_to_radius_attr[ldap_attr] = {'radius_attr':radius_attr, 'attr_type':attr_type}
        f.close()
    except Exception, e:
        logging.error('cold not read radius ldap attribute map file (%s): %s', LDAP_ATTR_MAP_FILEPATH, e)
        pass                    # FIXME

    #for k,v in radius_attr_to_ldap_attr.items():
    #    print '%s --> %s' % (k,v)
    #for k,v in ldap_attr_to_radius_attr.items():
    #    print '%s --> %s' % (k,v)

