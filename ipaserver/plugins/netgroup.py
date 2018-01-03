# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

import six

from ipalib import api, errors
from ipalib import Str, StrEnum, Flag
from ipalib.plugable import Registry
from .baseldap import (
    external_host_param,
    add_external_pre_callback,
    add_external_post_callback,
    remove_external_post_callback,
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPAddMember,
    LDAPRemoveMember)
from ipalib import _, ngettext
from .hbacrule import is_all
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
Netgroups

A netgroup is a group used for permission checking. It can contain both
user and host values.

EXAMPLES:

 Add a new netgroup:
   ipa netgroup-add --desc="NFS admins" admins

 Add members to the netgroup:
   ipa netgroup-add-member --users=tuser1 --users=tuser2 admins

 Remove a member from the netgroup:
   ipa netgroup-remove-member --users=tuser2 admins

 Display information about a netgroup:
   ipa netgroup-show admins

 Delete a netgroup:
   ipa netgroup-del admins
""")

register = Registry()

NETGROUP_PATTERN='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*$'
NETGROUP_PATTERN_ERRMSG='may only include letters, numbers, _, -, and .'

# according to most common use cases the netgroup pattern should fit
# also the nisdomain pattern
NISDOMAIN_PATTERN=NETGROUP_PATTERN
NISDOMAIN_PATTERN_ERRMSG=NETGROUP_PATTERN_ERRMSG

output_params = (
        Str('memberuser_user?',
            label='Member User',
        ),
        Str('memberuser_group?',
            label='Member Group',
        ),
        Str('memberhost_host?',
            label=_('Member Host'),
        ),
        Str('memberhost_hostgroup?',
            label='Member Hostgroup',
        ),
    )


@register()
class netgroup(LDAPObject):
    """
    Netgroup object.
    """
    container_dn = api.env.container_netgroup
    object_name = _('netgroup')
    object_name_plural = _('netgroups')
    object_class = ['ipaobject', 'ipaassociation', 'ipanisnetgroup']
    permission_filter_objectclasses = ['ipanisnetgroup']
    search_attributes = [
        'cn', 'description', 'memberof', 'externalhost', 'nisdomainname',
        'memberuser', 'memberhost', 'member', 'usercategory', 'hostcategory',
    ]
    default_attributes = [
        'cn', 'description', 'memberof', 'externalhost', 'nisdomainname',
        'memberuser', 'memberhost', 'member', 'memberindirect',
        'usercategory', 'hostcategory',
    ]
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['netgroup'],
        'memberof': ['netgroup'],
        'memberindirect': ['netgroup'],
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
    }
    relationships = {
        'member': ('Member', '', 'no_'),
        'memberof': ('Member Of', 'in_', 'not_in_'),
        'memberindirect': (
            'Indirect Member', None, 'no_indirect_'
        ),
        'memberuser': ('Member', '', 'no_'),
        'memberhost': ('Member', '', 'no_'),
    }
    managed_permissions = {
        'System: Read Netgroups': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'description', 'hostcategory', 'ipaenabledflag',
                'ipauniqueid', 'nisdomainname', 'usercategory', 'objectclass',
            },
        },
        'System: Read Netgroup Membership': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'externalhost', 'member', 'memberof', 'memberuser',
                'memberhost', 'objectclass',
            },
        },
        'System: Add Netgroups': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=ng,cn=alt,$SUFFIX")(version 3.0;acl "permission:Add netgroups";allow (add) groupdn = "ldap:///cn=Add netgroups,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Netgroups Administrators'},
        },
        'System: Modify Netgroup Membership': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'externalhost', 'member', 'memberhost', 'memberuser'
            },
            'replaces': [
                '(targetattr = "memberhost || externalhost || memberuser || member")(target = "ldap:///ipauniqueid=*,cn=ng,cn=alt,$SUFFIX")(version 3.0;acl "permission:Modify netgroup membership";allow (write) groupdn = "ldap:///cn=Modify netgroup membership,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Netgroups Administrators'},
        },
        'System: Modify Netgroups': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'description'},
            'replaces': [
                '(targetattr = "description")(target = "ldap:///ipauniqueid=*,cn=ng,cn=alt,$SUFFIX")(version 3.0; acl "permission:Modify netgroups";allow (write) groupdn = "ldap:///cn=Modify netgroups,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Netgroups Administrators'},
        },
        'System: Remove Netgroups': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=ng,cn=alt,$SUFFIX")(version 3.0;acl "permission:Remove netgroups";allow (delete) groupdn = "ldap:///cn=Remove netgroups,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'Netgroups Administrators'},
        },
        'System: Read Netgroup Compat Tree': {
            'non_object': True,
            'ipapermbindruletype': 'anonymous',
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=ng', 'cn=compat', api.env.basedn),
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'membernisnetgroup', 'nisnetgrouptriple',
            },
        },
    }

    label = _('Netgroups')
    label_singular = _('Netgroup')

    takes_params = (
        Str('cn',
            pattern=NETGROUP_PATTERN,
            pattern_errmsg=NETGROUP_PATTERN_ERRMSG,
            cli_name='name',
            label=_('Netgroup name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('Netgroup description'),
        ),
        Str('nisdomainname?',
            pattern=NISDOMAIN_PATTERN,
            pattern_errmsg=NISDOMAIN_PATTERN_ERRMSG,
            cli_name='nisdomain',
            label=_('NIS domain name'),
        ),
        Str('ipauniqueid?',
            cli_name='uuid',
            label='IPA unique ID',
            doc=_('IPA unique ID'),
            flags=['no_create', 'no_update'],
        ),
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
        external_host_param,
    )

    def get_primary_key_from_dn(self, dn):
        assert isinstance(dn, DN)
        if not dn.rdns:
            return u''

        first_ava = dn.rdns[0][0]
        if first_ava[0] == self.primary_key.name:
            return unicode(first_ava[1])

        try:
            entry_attrs = self.backend.get_entry(
                dn, [self.primary_key.name]
            )
            try:
                return entry_attrs[self.primary_key.name][0]
            except (KeyError, IndexError):
                return u''
        except errors.NotFound:
            return unicode(dn)


@register()
class netgroup_add(LDAPCreate):
    __doc__ = _('Add a new netgroup.')

    has_output_params = LDAPCreate.has_output_params + output_params
    msg_summary = _('Added netgroup "%(value)s"')

    msg_collision = _(u'hostgroup with name "%s" already exists. ' \
                      u'Hostgroups and netgroups share a common namespace')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        entry_attrs.setdefault('nisdomainname', self.api.env.domain)

        try:
            test_dn = self.obj.get_dn(keys[-1])
            netgroup = ldap.get_entry(test_dn, ['objectclass'])
            if 'mepManagedEntry' in netgroup.get('objectclass', []):
                raise errors.DuplicateEntry(message=unicode(self.msg_collision % keys[-1]))
            else:
                self.obj.handle_duplicate_entry(*keys)
        except errors.NotFound:
            pass

        try:
            # when enabled, a managed netgroup is created for every hostgroup
            # make sure that we don't create a collision if the plugin is
            # (temporarily) disabled
            api.Object['hostgroup'].get_dn_if_exists(keys[-1])
            raise errors.DuplicateEntry(message=unicode(self.msg_collision % keys[-1]))
        except errors.NotFound:
            pass

        return dn


@register()
class netgroup_del(LDAPDelete):
    __doc__ = _('Delete a netgroup.')

    msg_summary = _('Deleted netgroup "%(value)s"')



@register()
class netgroup_mod(LDAPUpdate):
    __doc__ = _('Modify a netgroup.')

    has_output_params = LDAPUpdate.has_output_params + output_params
    msg_summary = _('Modified netgroup "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, attrs_list)
            dn = entry_attrs.dn
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)
        if is_all(options, 'usercategory') and 'memberuser' in entry_attrs:
            raise errors.MutuallyExclusiveError(
                reason=_("user category cannot be set to 'all' while there "
                         "are allowed users")
            )
        if is_all(options, 'hostcategory') and 'memberhost' in entry_attrs:
            raise errors.MutuallyExclusiveError(
                reason=_("host category cannot be set to 'all' while there "
                         "are allowed hosts")
            )
        return dn


@register()
class netgroup_find(LDAPSearch):
    __doc__ = _('Search for a netgroup.')

    member_attributes = ['member', 'memberuser', 'memberhost', 'memberof']
    has_output_params = LDAPSearch.has_output_params + output_params
    msg_summary = ngettext(
        '%(count)d netgroup matched', '%(count)d netgroups matched', 0
    )

    takes_options = LDAPSearch.takes_options + (
        Flag('private',
            exclude='webui',
            flags=['no_option', 'no_output'],
        ),
        Flag('managed',
            cli_name='managed',
            doc=_('search for managed groups'),
            default_from=lambda private: private,
        ),
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        # Do not display private mepManagedEntry netgroups by default
        # If looking for managed groups, we need to omit the negation search filter

        search_kw = {}
        search_kw['objectclass'] = ['mepManagedEntry']
        if not options['managed']:
            local_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_NONE)
        else:
            local_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        filter = ldap.combine_filters((local_filter, filter), rules=ldap.MATCH_ALL)
        return (filter, base_dn, scope)


@register()
class netgroup_show(LDAPRetrieve):
    __doc__ = _('Display information about a netgroup.')

    has_output_params = LDAPRetrieve.has_output_params + output_params


@register()
class netgroup_add_member(LDAPAddMember):
    __doc__ = _('Add members to a netgroup.')

    member_attributes = ['memberuser', 'memberhost', 'member']
    has_output_params = LDAPAddMember.has_output_params + output_params

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        return add_external_pre_callback('host', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)
        return add_external_post_callback(ldap, dn, entry_attrs,
                                          failed=failed,
                                          completed=completed,
                                          memberattr='memberhost',
                                          membertype='host',
                                          externalattr='externalhost')


@register()
class netgroup_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from a netgroup.')

    member_attributes = ['memberuser', 'memberhost', 'member']
    has_output_params = LDAPRemoveMember.has_output_params + output_params

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        assert isinstance(dn, DN)
        return remove_external_post_callback(ldap, dn, entry_attrs,
                                             failed=failed,
                                             completed=completed,
                                             memberattr='memberhost',
                                             membertype='host',
                                             externalattr='externalhost')
