# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
"""
Host based access control
"""

from ipalib import api, errors
from ipalib import AccessTime, Password, Str, StrEnum
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext

class hbac(LDAPObject):
    """
    HBAC object.
    """
    container_dn = api.env.container_hbac
    object_name = 'HBAC rule'
    object_name_plural = 'HBAC rules'
    object_class = ['ipaassociation', 'ipahbacrule']
    default_attributes = [
        'cn', 'accessruletype', 'ipaenabledflag', 'servicename',
        'accesstime', 'description',

    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
        'sourcehost': ['host', 'hostgroup'],
    }

    label = _('HBAC')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Rule name'),
            primary_key=True,
        ),
        StrEnum('accessruletype',
            cli_name='type',
            label=_('Rule type (allow or deny)'),
            values=(u'allow', u'deny'),
        ),
        Str('servicename?',
            cli_name='service',
            label=_('Service name'),
            doc=_('Name of service the rule applies to (e.g. ssh)'),
        ),
        # FIXME: {user,host,sourcehost}categories should expand in the future
        StrEnum('usercategory?',
            cli_name='usercat',
            label=_('User category'),
            doc=_('User category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('hostcategory?',
            cli_name='hostcat',
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('sourcehostcategory?',
            cli_name='srchostcat',
            label=_('Source host category'),
            doc=_('Source host category the rule applies to'),
            values=(u'all', ),
        ),
        AccessTime('accesstime?',
            cli_name='time',
            label=_('Access time'),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
    )

    def get_dn(self, *keys, **kwargs):
        try:
            (dn, entry_attrs) = self.backend.find_entry_by_attr(
                self.primary_key.name, keys[-1], self.object_class, [''],
                self.container_dn
            )
        except errors.NotFound:
            dn = super(hbac, self).get_dn(*keys, **kwargs)
        return dn

    def get_primary_key_from_dn(self, dn):
        pkey = self.primary_key.name
        (dn, entry_attrs) = self.backend.get_entry(dn, [pkey])
        try:
            return entry_attrs[pkey][0]
        except (KeyError, IndexError):
            return ''

api.register(hbac)


class hbac_add(LDAPCreate):
    """
    Create new HBAC rule.
    """
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if not dn.startswith('cn='):
            msg = 'HBAC rule with name "%s" already exists' % keys[-1]
            raise errors.DuplicateEntry(message=msg)
        # HBAC rules are enabled by default
        entry_attrs['ipaenabledflag'] = 'TRUE'
        return ldap.make_dn(
            entry_attrs, self.obj.uuid_attribute, self.obj.container_dn
        )

api.register(hbac_add)


class hbac_del(LDAPDelete):
    """
    Delete HBAC rule.
    """

api.register(hbac_del)


class hbac_mod(LDAPUpdate):
    """
    Modify HBAC rule.
    """

api.register(hbac_mod)


class hbac_find(LDAPSearch):
    """
    Search for HBAC rules.
    """

api.register(hbac_find)


class hbac_show(LDAPRetrieve):
    """
    Dispaly HBAC rule.
    """

api.register(hbac_show)


class hbac_enable(LDAPQuery):
    """
    Enable HBAC rule.
    """
    def execute(self, cn):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        entry_attrs = {'ipaenabledflag': 'TRUE'}

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(result=True)

    def output_for_cli(self, textui, result, cn):
        textui.print_name(self.name)
        textui.print_dashed('Enabled HBAC rule "%s".' % cn)

api.register(hbac_enable)


class hbac_disable(LDAPQuery):
    """
    Disable HBAC rule.
    """
    def execute(self, cn):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        entry_attrs = {'ipaenabledflag': 'FALSE'}

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(result=True)

    def output_for_cli(self, textui, result, cn):
        textui.print_name(self.name)
        textui.print_dashed('Disabled HBAC rule "%s".' % cn)

api.register(hbac_disable)


class hbac_add_accesstime(LDAPQuery):
    """
    Add access time to HBAC rule.
    """

    takes_options = (
        AccessTime('accesstime',
            cli_name='time',
            label=_('Access time'),
        ),
    )

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)

        (dn, entry_attrs) = ldap.get_entry(dn, ['accesstime'])
        entry_attrs.setdefault('accesstime', []).append(
            options['accesstime']
        )
        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(result=True)

    def output_for_cli(self, textui, result, cn, **options):
        textui.print_name(self.name)
        textui.print_dashed(
            'Added access time "%s" to HBAC rule "%s"' % (
                options['accesstime'], cn
            )
        )

api.register(hbac_add_accesstime)


class hbac_remove_accesstime(LDAPQuery):
    """
    Remove access time to HBAC rule.
    """
    takes_options = (
        AccessTime('accesstime?',
            cli_name='time',
            label=_('Access time'),
        ),
    )

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)

        (dn, entry_attrs) = ldap.get_entry(dn, ['accesstime'])
        try:
            entry_attrs.setdefault('accesstime', []).remove(
                options['accesstime']
            )
            ldap.update_entry(dn, entry_attrs)
        except (ValueError, errors.EmptyModlist):
            pass

        return dict(result=True)

    def output_for_cli(self, textui, result, cn, **options):
        textui.print_name(self.name)
        textui.print_dashed(
            'Removed access time "%s" from HBAC rule "%s"' % (
                options['accesstime'], cn
            )
        )

api.register(hbac_remove_accesstime)


class hbac_add_user(LDAPAddMember):
    """
    Add users and groups affected by HBAC rule.
    """
    member_attributes = ['memberuser']
    member_count_out = ('%i object added.', '%i objects added.')

api.register(hbac_add_user)


class hbac_remove_user(LDAPRemoveMember):
    """
    Remove users and groups affected by HBAC rule.
    """
    member_attributes = ['memberuser']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(hbac_remove_user)


class hbac_add_host(LDAPAddMember):
    """
    Add hosts and hostgroups affected by HBAC rule.
    """
    member_attributes = ['memberhost']
    member_count_out = ('%i object added.', '%i objects added.')

api.register(hbac_add_host)


class hbac_remove_host(LDAPRemoveMember):
    """
    Remove hosts and hostgroups affected by HBAC rule.
    """
    member_attributes = ['memberhost']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(hbac_remove_host)


class hbac_add_sourcehost(LDAPAddMember):
    """
    Add source hosts and hostgroups affected by HBAC rule.
    """
    member_attributes = ['sourcehost']
    member_count_out = ('%i object added.', '%i objects added.')

api.register(hbac_add_sourcehost)


class hbac_remove_sourcehost(LDAPRemoveMember):
    """
    Remove source hosts and hostgroups affected by HBAC rule.
    """
    member_attributes = ['sourcehost']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(hbac_remove_sourcehost)
