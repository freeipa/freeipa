# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from ipalib import api
from ipalib import Str
from ipalib.plugable import Registry
from .baseldap import LDAPObject, LDAPCreate, LDAPDelete
from .baseldap import LDAPUpdate, LDAPSearch, LDAPRetrieve

from ipalib import _, ngettext

__doc__ = _("""
HBAC Services

The PAM services that HBAC can control access to. The name used here
must match the service name that PAM is evaluating.

EXAMPLES:

 Add a new HBAC service:
   ipa hbacsvc-add tftp

 Modify an existing HBAC service:
   ipa hbacsvc-mod --desc="TFTP service" tftp

 Search for HBAC services. This example will return two results, the FTP
 service and the newly-added tftp service:
   ipa hbacsvc-find ftp

 Delete an HBAC service:
   ipa hbacsvc-del tftp

""")

register = Registry()

topic = 'hbac'

@register()
class hbacsvc(LDAPObject):
    """
    HBAC Service object.
    """
    container_dn = api.env.container_hbacservice
    object_name = _('HBAC service')
    object_name_plural = _('HBAC services')
    object_class = [ 'ipaobject', 'ipahbacservice' ]
    permission_filter_objectclasses = ['ipahbacservice']
    default_attributes = ['cn', 'description', 'memberof']
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'memberof': ['hbacsvcgroup'],
    }
    managed_permissions = {
        'System: Read HBAC Services': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'description', 'ipauniqueid', 'memberof', 'objectclass',
            },
        },
        'System: Add HBAC Services': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=hbacservices,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Add HBAC services";allow (add) groupdn = "ldap:///cn=Add HBAC services,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
        'System: Delete HBAC Services': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=hbacservices,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Delete HBAC services";allow (delete) groupdn = "ldap:///cn=Delete HBAC services,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
    }

    label = _('HBAC Services')
    label_singular = _('HBAC Service')

    takes_params = (
        Str('cn',
            cli_name='service',
            label=_('Service name'),
            doc=_('HBAC service'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('HBAC service description'),
        ),
    )



@register()
class hbacsvc_add(LDAPCreate):
    __doc__ = _('Add a new HBAC service.')

    msg_summary = _('Added HBAC service "%(value)s"')



@register()
class hbacsvc_del(LDAPDelete):
    __doc__ = _('Delete an existing HBAC service.')

    msg_summary = _('Deleted HBAC service "%(value)s"')



@register()
class hbacsvc_mod(LDAPUpdate):
    __doc__ = _('Modify an HBAC service.')

    msg_summary = _('Modified HBAC service "%(value)s"')



@register()
class hbacsvc_find(LDAPSearch):
    __doc__ = _('Search for HBAC services.')

    msg_summary = ngettext(
        '%(count)d HBAC service matched', '%(count)d HBAC services matched', 0
    )



@register()
class hbacsvc_show(LDAPRetrieve):
    __doc__ = _('Display information about an HBAC service.')
