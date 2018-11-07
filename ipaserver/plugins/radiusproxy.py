# Authors:
#   Nathaniel McCallum <npmccallum@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve)
from ipalib import api, Str, Int, Password, _, ngettext
from ipalib import errors
from ipalib.plugable import Registry
from ipalib.util import validate_hostname, validate_ipaddr
from ipalib.errors import ValidationError
from ipapython.dn import DN
import re

__doc__ = _("""
RADIUS Proxy Servers
""") + _("""
Manage RADIUS Proxy Servers.
""") + _("""
IPA supports the use of an external RADIUS proxy server for krb5 OTP
authentications. This permits a great deal of flexibility when
integrating with third-party authentication services.
""") + _("""
EXAMPLES:
""") + _("""
 Add a new server:
   ipa radiusproxy-add MyRADIUS --server=radius.example.com:1812
""") + _("""
 Find all servers whose entries include the string "example.com":
   ipa radiusproxy-find example.com
""") + _("""
 Examine the configuration:
   ipa radiusproxy-show MyRADIUS
""") + _("""
 Change the secret:
   ipa radiusproxy-mod MyRADIUS --secret
""") + _("""
 Delete a configuration:
   ipa radiusproxy-del MyRADIUS
""")

register = Registry()

LDAP_ATTRIBUTE = re.compile("^[a-zA-Z][a-zA-Z0-9-]*$")
def validate_attributename(ugettext, attr):
    if not LDAP_ATTRIBUTE.match(attr):
        raise ValidationError(name="ipatokenusermapattribute",
                              error=_('invalid attribute name'))

def validate_radiusserver(ugettext, server):
    split = server.rsplit(':', 1)
    server = split[0]
    if len(split) == 2:
        try:
            port = int(split[1])
            if (port < 0 or port > 65535):
                raise ValueError()
        except ValueError:
            raise ValidationError(name="ipatokenradiusserver",
                                  error=_('invalid port number'))

    if validate_ipaddr(server):
        return

    try:
        validate_hostname(server, check_fqdn=True, allow_underscore=True)
    except ValueError as e:
        raise errors.ValidationError(name="ipatokenradiusserver",
                                     error=str(e))


@register()
class radiusproxy(LDAPObject):
    """
    RADIUS Server object.
    """
    container_dn = api.env.container_radiusproxy
    object_name = _('RADIUS proxy server')
    object_name_plural = _('RADIUS proxy servers')
    object_class = ['ipatokenradiusconfiguration']
    default_attributes = ['cn', 'description', 'ipatokenradiusserver',
        'ipatokenradiustimeout', 'ipatokenradiusretries', 'ipatokenusermapattribute'
    ]
    search_attributes = ['cn', 'description', 'ipatokenradiusserver']
    allow_rename = True
    label = _('RADIUS Servers')
    label_singular = _('RADIUS Server')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('RADIUS proxy server name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this RADIUS proxy server'),
        ),
        Str('ipatokenradiusserver', validate_radiusserver,
            cli_name='server',
            label=_('Server'),
            doc=_('The hostname or IP (with or without port)'),
        ),
        Password('ipatokenradiussecret',
            cli_name='secret',
            label=_('Secret'),
            doc=_('The secret used to encrypt data'),
            confirm=True,
        ),
        Int('ipatokenradiustimeout?',
            cli_name='timeout',
            label=_('Timeout'),
            doc=_('The total timeout across all retries (in seconds)'),
            minvalue=1,
        ),
        Int('ipatokenradiusretries?',
            cli_name='retries',
            label=_('Retries'),
            doc=_('The number of times to retry authentication'),
            minvalue=0,
            maxvalue=10,
        ),
        Str('ipatokenusermapattribute?', validate_attributename,
            cli_name='userattr',
            label=_('User attribute'),
            doc=_('The username attribute on the user object'),
        ),
    )

    managed_permissions = {
        'System: Read Radius Servers': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'ipatokenradiusserver', 'description',
                'ipatokenradiustimeout', 'ipatokenradiusretries',
                'ipatokenusermapattribute'
            },
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermtargetfilter': {
                '(objectclass=ipatokenradiusconfiguration)'},
            'default_privileges': {
                'User Administrators',
                'Stage User Administrators'},
        }
    }

@register()
class radiusproxy_add(LDAPCreate):
    __doc__ = _('Add a new RADIUS proxy server.')
    msg_summary = _('Added RADIUS proxy server "%(value)s"')

@register()
class radiusproxy_del(LDAPDelete):
    __doc__ = _('Delete a RADIUS proxy server.')
    msg_summary = _('Deleted RADIUS proxy server "%(value)s"')

@register()
class radiusproxy_mod(LDAPUpdate):
    __doc__ = _('Modify a RADIUS proxy server.')
    msg_summary = _('Modified RADIUS proxy server "%(value)s"')

@register()
class radiusproxy_find(LDAPSearch):
    __doc__ = _('Search for RADIUS proxy servers.')
    msg_summary = ngettext(
        '%(count)d RADIUS proxy server matched', '%(count)d RADIUS proxy servers matched', 0
    )

    def get_options(self):
        for option in super(radiusproxy_find, self).get_options():
            if option.name == 'ipatokenradiussecret':
                option = option.clone(flags={'no_option'})

            yield option


@register()
class radiusproxy_show(LDAPRetrieve):
    __doc__ = _('Display information about a RADIUS proxy server.')
