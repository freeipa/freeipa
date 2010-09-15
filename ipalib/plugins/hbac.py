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
Host-based access control

Control who can access what services on what hosts and from where. You
can use HBAC to control which users or groups on a source host can
access a service, or group of services, on a target host. You can also
control the times that the rule is active.

You can also specify a category of users, target hosts, and source
hosts. This is currently limited to "all", but might be expanded in the
future.

The access time(s) of a host are cumulative and are not guaranteed to be
applied in the order displayed.

Target hosts and source hosts in HBAC rules must be hosts managed by IPA.

The available services and groups of services are controlled by the
hbacsvc and hbacsvcgroup plug-ins respectively.

EXAMPLES:

 Create a rule, "test1", that grants all users access to the host "server" from
 anywhere:
   ipa hbac-add --type=allow --usercat=all --srchostcat=all test1
   ipa hbac-add-host --hosts=server.example.com test1

 Display the properties of a named HBAC rule:
   ipa hbac-show test1

 Specify that the rule "test1" be active every day between 0800 and 1400:
   ipa hbac-add-accesstime --time='periodic daily 0800-1400' test1

  Specify that the rule "test1" be active once, from 10:32 until 10:33 on
  December 16, 2010:
   ipa hbac-add-accesstime --time='absolute 201012161032 ~ 201012161033' test1

 Create a rule for a specific service. This lets the user john access
 the sshd service on any machine from any machine:
   ipa hbac-add --type=allow --hostcat=all --srchostcat=all john_sshd
   ipa hbac-add-user --users=john john_sshd
   ipa hbac-add-service --hbacsvcs=sshd john_sshd

 Create a rule for a new service group. This lets the user john access
 the any FTP service on any machine from any machine:
   ipa hbacsvcgroup-add ftpers
   ipa hbacsvc-add sftp
   ipa hbacsvcgroup-add-member --hbacsvcs=ftp,sftp ftpers
   ipa hbac-add --type=allow --hostcat=all --srchostcat=all john_ftp
   ipa hbac-add-user --users=john john_ftp
   ipa hbac-add-service --hbacsvcgroups=ftpers john_ftp

 Disable a named HBAC rule:
   ipa hbac-disable test1

 Remove a named HBAC rule:
   ipa hbac-del allow_server
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
        'cn', 'accessruletype', 'ipaenabledflag',
        'accesstime', 'description', 'usercategory', 'hostcategory',
        'sourcehostcategory', 'servicecategory', 'ipaenabledflag',
        'memberuser', 'sourcehost', 'memberhost', 'memberservice',
        'memberhostgroup',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
        'sourcehost': ['host', 'hostgroup'],
        'memberservice': ['hbacsvc', 'hbacsvcgroup'],
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
            doc=_('Rule type (allow or deny)'),
            label=_('Rule type'),
            values=(u'allow', u'deny'),
        ),
        # FIXME: {user,host,sourcehost,service}categories should expand in the future
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
        StrEnum('servicecategory?',
            cli_name='servicecat',
            label=_('Service category'),
            doc=_('Service category the rule applies to'),
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
        Flag('ipaenabledflag?',
             label=_('Enabled'),
             flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberuser_user?',
            label=_('Users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_host?',
            label=_('Hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_hostgroup?',
            label=_('Host Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('sourcehost_host?',
            label=_('Source hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberservice_service?',
            label=_('Services'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberservice_servicegroup?',
            label=_('Service Groups'),
            flags=['no_create', 'no_update', 'no_search'],
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
    Create a new HBAC rule.
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
    Delete an HBAC rule.
    """

api.register(hbac_del)


class hbac_mod(LDAPUpdate):
    """
    Modify an HBAC rule.
    """

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)
        if 'usercategory' in options and options['usercategory'].lower() == 'all' and \
            'memberuser' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason="user category cannot be set to 'all' while there are allowed users")
        if 'hostcategory' in options and options['hostcategory'].lower() == 'all' and \
            'memberhost' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason="host category cannot be set to 'all' while there are allowed hosts")
        if 'sourcehostcategory' in options and options['sourcehostcategory'].lower() == 'all' and \
            'sourcehost' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason="sourcehost category cannot be set to 'all' while there are allowed source hosts")
        if 'servicecategory' in options and options['servicecategory'].lower() == 'all' and \
            'memberservice' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason="service category cannot be set to 'all' while there are allowed services")
        return dn

api.register(hbac_mod)


class hbac_find(LDAPSearch):
    """
    Search for HBAC rules.
    """

api.register(hbac_find)


class hbac_show(LDAPRetrieve):
    """
    Display the properties of an HBAC rule.
    """

api.register(hbac_show)


class hbac_enable(LDAPQuery):
    """
    Enable an HBAC rule.
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
    Disable an HBAC rule.
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
    Add an access time to an HBAC rule.
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
    Add users and groups to an HBAC rule.
    """
    member_attributes = ['memberuser']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        (dn, entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        if 'usercategory' in entry_attrs and \
            entry_attrs['usercategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(reason="users cannot be added when user category='all'")
        return dn

api.register(hbac_add_user)


class hbac_remove_user(LDAPRemoveMember):
    """
    Remove users and groups from an HBAC rule.
    """
    member_attributes = ['memberuser']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(hbac_remove_user)


class hbac_add_host(LDAPAddMember):
    """
    Add target hosts and hostgroups to an HBAC rule
    """
    member_attributes = ['memberhost']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        (dn, entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        if 'hostcategory' in entry_attrs and \
            entry_attrs['hostcategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(reason="hosts cannot be added when host category='all'")
        return dn

api.register(hbac_add_host)


class hbac_remove_host(LDAPRemoveMember):
    """
    Remove target hosts and hostgroups from a HBAC rule.
    """
    member_attributes = ['memberhost']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(hbac_remove_host)


class hbac_add_sourcehost(LDAPAddMember):
    """
    Add source hosts and hostgroups from a HBAC rule.
    """
    member_attributes = ['sourcehost']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        (dn, entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        if 'sourcehostcategory' in entry_attrs and \
            entry_attrs['sourcehostcategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(reason="source hosts cannot be added when sourcehost category='all'")
        return dn

api.register(hbac_add_sourcehost)


class hbac_remove_sourcehost(LDAPRemoveMember):
    """
    Remove source hosts and hostgroups from an HBAC rule.
    """
    member_attributes = ['sourcehost']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(hbac_remove_sourcehost)


class hbac_add_service(LDAPAddMember):
    """
    Add services to an HBAC rule.
    """
    member_attributes = ['memberservice']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        (dn, entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)
        if 'servicecategory' in entry_attrs and \
            entry_attrs['servicecategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(reason="services cannot be added when service category='all'")
        return dn

api.register(hbac_add_service)


class hbac_remove_service(LDAPRemoveMember):
    """
    Remove source hosts and hostgroups from an HBAC rule.
    """
    member_attributes = ['memberservice']
    member_count_out = ('%i object removed.', '%i objects removed.')

api.register(hbac_remove_service)
