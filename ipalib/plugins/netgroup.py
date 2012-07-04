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


from ipalib import api, errors
from ipalib import Str, StrEnum
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
from ipalib.plugins.hbacrule import is_all

__doc__ = _("""
Netgroups

A netgroup is a group used for permission checking. It can contain both
user and host values.

EXAMPLES:

 Add a new netgroup:
   ipa netgroup-add --desc="NFS admins" admins

 Add members to the netgroup:
   ipa netgroup-add-member --users=tuser1,tuser2 admins

 Remove a member from the netgroup:
   ipa netgroup-remove-member --users=tuser2 admins

 Display information about a netgroup:
   ipa netgroup-show admins

 Delete a netgroup:
   ipa netgroup-del admins
""")


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

class netgroup(LDAPObject):
    """
    Netgroup object.
    """
    container_dn = api.env.container_netgroup
    object_name = _('netgroup')
    object_name_plural = _('netgroups')
    object_class = ['ipaobject', 'ipaassociation', 'ipanisnetgroup']
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
        Str('description',
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

api.register(netgroup)


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
            (test_dn_, netgroup) = ldap.get_entry(test_dn, ['objectclass'])
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
            netgroup = api.Command['hostgroup_show'](keys[-1])
            raise errors.DuplicateEntry(message=unicode(self.msg_collision % keys[-1]))
        except errors.NotFound:
            pass

        return dn

api.register(netgroup_add)


class netgroup_del(LDAPDelete):
    __doc__ = _('Delete a netgroup.')

    msg_summary = _('Deleted netgroup "%(value)s"')

api.register(netgroup_del)


class netgroup_mod(LDAPUpdate):
    __doc__ = _('Modify a netgroup.')

    has_output_params = LDAPUpdate.has_output_params + output_params
    msg_summary = _('Modified netgroup "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(options, 'usercategory') and 'memberuser' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("user category cannot be set to 'all' while there are allowed users"))
        if is_all(options, 'hostcategory') and 'memberhost' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("host category cannot be set to 'all' while there are allowed hosts"))
        return dn

api.register(netgroup_mod)


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

api.register(netgroup_find)


class netgroup_show(LDAPRetrieve):
    __doc__ = _('Display information about a netgroup.')

    has_output_params = LDAPRetrieve.has_output_params + output_params

api.register(netgroup_show)


class netgroup_add_member(LDAPAddMember):
    __doc__ = _('Add members to a netgroup.')

    member_attributes = ['memberuser', 'memberhost', 'member']
    has_output_params = LDAPAddMember.has_output_params + output_params
    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        return add_external_pre_callback('host', ldap, dn, keys, options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return add_external_post_callback('memberhost', 'host', 'externalhost', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(netgroup_add_member)


class netgroup_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from a netgroup.')

    member_attributes = ['memberuser', 'memberhost', 'member']
    has_output_params = LDAPRemoveMember.has_output_params + output_params
    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return remove_external_post_callback('memberhost', 'host', 'externalhost', ldap, completed, failed, dn, entry_attrs, keys, options)

api.register(netgroup_remove_member)
