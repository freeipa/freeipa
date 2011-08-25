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

from ipalib import api, errors
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext

__doc__ = _("""
HBAC Service Groups

HBAC service groups can contain any number of individual services,
or "members". Every group must have a description.

EXAMPLES:

 Add a new HBAC service group:
   ipa hbacsvcgroup-add --desc="login services" login

 Add members to an HBAC service group:
   ipa hbacsvcgroup-add-member --hbacsvcs=sshd,login login

 Display information about a named group:
   ipa hbacsvcgroup-show login

 Add a new group to the "login" group:
   ipa hbacsvcgroup-add --desc="switch users" login
   ipa hbacsvcgroup-add-member --hbacsvcs=su,su-l login

 Delete an HBAC service group:
   ipa hbacsvcgroup-del login
""")

topic = ('hbac', _('Host based access control commands'))

class hbacsvcgroup(LDAPObject):
    """
    HBAC service group object.
    """
    container_dn = api.env.container_hbacservicegroup
    object_name = _('HBAC service group')
    object_name_plural = _('HBAC service groups')
    object_class = ['ipaobject', 'ipahbacservicegroup']
    default_attributes = [ 'cn', 'description', 'member' ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['hbacsvc'],
    }

    label = _('HBAC Service Groups')
    label_singular = _('HBAC Service Group')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Service group name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('HBAC service group description'),
        ),
    )

api.register(hbacsvcgroup)


class hbacsvcgroup_add(LDAPCreate):
    __doc__ = _('Add a new HBAC service group.')

    msg_summary = _('Added HBAC service group "%(value)s"')

api.register(hbacsvcgroup_add)


class hbacsvcgroup_del(LDAPDelete):
    __doc__ = _('Delete an HBAC service group.')

    msg_summary = _('Deleted HBAC service group "%(value)s"')

api.register(hbacsvcgroup_del)


class hbacsvcgroup_mod(LDAPUpdate):
    __doc__ = _('Modify an HBAC service group.')

    msg_summary = _('Modified HBAC service group "%(value)s"')

api.register(hbacsvcgroup_mod)


class hbacsvcgroup_find(LDAPSearch):
    __doc__ = _('Search for an HBAC service group.')

    msg_summary = ngettext(
        '%(count)d HBAC service group matched', '%(count)d HBAC service groups matched', 0
    )

api.register(hbacsvcgroup_find)


class hbacsvcgroup_show(LDAPRetrieve):
    __doc__ = _('Display information about an HBAC service group.')

api.register(hbacsvcgroup_show)


class hbacsvcgroup_add_member(LDAPAddMember):
    __doc__ = _('Add members to an HBAC service group.')

api.register(hbacsvcgroup_add_member)


class hbacsvcgroup_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from an HBAC service group.')

api.register(hbacsvcgroup_remove_member)
