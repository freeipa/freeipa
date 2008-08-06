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
import getpass
import ldap.filter

from ipa import ipautil
from ipa.entity import Entity
import ipa.ipavalidate as ipavalidate


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

    'RadiusClient',
    'RadiusProfile',

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

    'get_secret',
    'validate_ip_addr',
    'validate_secret',
    'validate_name',
    'validate_nastype',
    'validate_desc',
    'validate',
    ]

#------------------------------------------------------------------------------

RADIUS_PKG_NAME = 'freeradius'
RADIUS_PKG_CONFIG_DIR      = '/etc/raddb'

RADIUS_SERVICE_NAME = 'radius'
RADIUS_USER         = 'radiusd'

RADIUS_IPA_KEYTAB_FILEPATH     = os.path.join(RADIUS_PKG_CONFIG_DIR, 'ipa.keytab')
RADIUS_LDAP_ATTR_MAP_FILEPATH  = os.path.join(RADIUS_PKG_CONFIG_DIR, 'ldap.attrmap')
RADIUSD_CONF_FILEPATH          = os.path.join(RADIUS_PKG_CONFIG_DIR, 'radiusd.conf')
RADIUSD_CONF_TEMPLATE_FILEPATH = os.path.join(ipautil.PLUGINS_SHARE_DIR,     'radius.radiusd.conf.template')

RADIUSD = '/usr/sbin/radiusd'

#------------------------------------------------------------------------------

dotted_octet_re = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)(/(\d+))?$")
dns_re = re.compile(r"^[a-zA-Z][a-zA-Z0-9.-]+$")
# secret, name, nastype all have 31 char max in freeRADIUS, max ip address len is 255
valid_secret_len = (1,31)
valid_name_len = (1,31)
valid_nastype_len = (1,31)
valid_ip_addr_len = (1,255)

valid_ip_addr_msg = '''\
IP address must be either a DNS name (letters,digits,dot,hyphen, beginning with
a letter),or a dotted octet followed by an optional mask (e.g 192.168.1.0/24)'''

valid_desc_msg = "Description must text string"

#------------------------------------------------------------------------------

class RadiusClient(Entity):

    def __init2__(self):
        pass

class RadiusProfile(Entity):

    def __init2__(self):
        pass
        

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

radius_profile_ldap_attr_to_radius_attr = ipautil.CIDict({
    'uid'                           : 'UID',
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
})

radius_profile_attr_to_ldap_attr = reverse_map_dict(radius_profile_ldap_attr_to_radius_attr)

#------------------------------------------------------------------------------

clients_container = 'cn=clients,cn=radius'

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

profiles_container = 'cn=profiles,cn=radius'

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

def get_secret():
    valid = False
    while (not valid):
        secret = getpass.getpass("Enter Secret: ")
        confirm = getpass.getpass("Confirm Secret: ")
        if (secret != confirm):
            print "Secrets do not match"
            continue
        valid = True
    return secret

#------------------------------------------------------------------------------

def valid_ip_addr(text):

    # is it a dotted octet? If so there should be 4 integers seperated
    # by a dot and each integer should be between 0 and 255
    # there may be an optional mask preceded by a slash (e.g. 1.2.3.4/24)
    match = dotted_octet_re.search(text)
    if match:
        # dotted octet notation
        i = 1
        while i <= 4:
            octet = int(match.group(i))
            if octet > 255: return False
            i += 1
        if match.group(5):
            mask = int(match.group(6))
            if mask <= 32:
                return True
            else:
                return False
        return True
    else:
        # DNS name, can contain letters, numbers, dot and hypen, must start with a letter
        if dns_re.search(text): return True
    return False

def validate_length(value, limits):
    length = len(value)
    if length < limits[0] or length > limits[1]:
        return False
    return True

def valid_length_msg(name, limits):
    return "%s length must be at least %d and not more than %d" % (name, limits[0], limits[1])

def err_msg(variable, variable_name=None):
    if variable_name is None: variable_name = 'value'
    print "ERROR: %s = %s" % (variable_name, variable)

#------------------------------------------------------------------------------

def validate_ip_addr(ip_addr, variable_name=None):
    if not validate_length(ip_addr, valid_ip_addr_len):
        err_msg(ip_addr, variable_name)
        print valid_length_msg('ip address', valid_ip_addr_len)
        return False
    if not valid_ip_addr(ip_addr):
        err_msg(ip_addr, variable_name)
        print valid_ip_addr_msg
        return False
    return True

def validate_secret(secret, variable_name=None):
    if not validate_length(secret, valid_secret_len):
        err_msg(secret, variable_name)
        print valid_length_msg('secret', valid_secret_len)
        return False
    return True

def validate_name(name, variable_name=None):
    if not validate_length(name, valid_name_len):
        err_msg(name, variable_name)
        print valid_length_msg('name', valid_name_len)
        return False
    return True

def validate_nastype(nastype, variable_name=None):
    if not validate_length(nastype, valid_nastype_len):
        err_msg(nastype, variable_name)
        print valid_length_msg('NAS Type', valid_nastype_len)
        return False
    return True

def validate_desc(desc, variable_name=None):
    if not ipavalidate.Plain(desc):
        print valid_desc_msg
        return False
    return True

def validate(attribute, value):
    if attribute == 'Client-IP-Address':
        return validate_ip_addr(value, attribute)
    if attribute == 'Secret':
        return validate_secret(value, attribute)
    if attribute == 'NAS-Type':
        return validate_nastype(value, attribute)
    if attribute == 'Name':
        return validate_name(value, attribute)
    if attribute == 'Description':
        return validate_desc(value, attribute)
    return True
