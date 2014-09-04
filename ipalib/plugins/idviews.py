# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from ipalib.plugins.baseldap import (LDAPQuery, LDAPObject, LDAPCreate,
                                     LDAPDelete, LDAPUpdate, LDAPSearch,
                                     LDAPRetrieve, global_output_params)
from ipalib.plugins.hostgroup import get_complete_hostgroup_member_list
from ipalib import api, Str, Int, Flag, _, ngettext, errors, output
from ipalib.constants import IPA_ANCHOR_PREFIX, SID_ANCHOR_PREFIX
from ipalib.plugable import Registry

from ipapython.dn import DN

if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc
        _dcerpc_bindings_installed = True
    except ImportError:
        _dcerpc_bindings_installed = False

__doc__ = _("""
ID views
Manage ID views
IPA allows to override certain properties of users and groups per each host.
This functionality is primarily used to allow migration from older systems or
other Identity Management solutions.
""")

register = Registry()


@register()
class idview(LDAPObject):
    """
    ID view object.
    """

    container_dn = api.env.container_views
    object_name = _('ID view')
    object_name_plural = _('ID views')
    object_class = ['ipaIDView', 'top']
    default_attributes = ['cn', 'description']
    rdn_is_primary_key = True

    label = _('ID views')
    label_singular = _('ID view')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('ID View Name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
    )

    permission_filter_objectclasses = ['nsContainer']
    managed_permissions = {
        'System: Read ID Views': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'description', 'objectClass',
            },
        },
    }


@register()
class idview_add(LDAPCreate):
    __doc__ = _('Add a new ID View.')
    msg_summary = _('Added ID view "%(value)s"')


@register()
class idview_del(LDAPDelete):
    __doc__ = _('Delete an ID view.')
    msg_summary = _('Deleted ID view "%(value)s"')


@register()
class idview_mod(LDAPUpdate):
    __doc__ = _('Modify an ID view.')
    msg_summary = _('Modified an ID view "%(value)s"')


@register()
class idview_find(LDAPSearch):
    __doc__ = _('Search for an ID view.')
    msg_summary = ngettext('%(count)d ID view matched',
                           '%(count)d ID views matched', 0)


@register()
class idview_show(LDAPRetrieve):
    __doc__ = _('Display information about an ID view.')

    takes_options = LDAPRetrieve.takes_options + (
        Flag('show_hosts?',
             cli_name='show_hosts',
             doc=_('Enumerate all the hosts the view applies to.'),
        ),
    )

    has_output_params = global_output_params + (
        Str('useroverrides',
            label=_('User object overrides'),
            ),
        Str('groupoverrides',
            label=_('Group object overrides'),
            ),
        Str('appliedtohosts',
            label=_('Hosts the view applies to')
        ),
    )

    def show_id_overrides(self, dn, entry_attrs):
        ldap = self.obj.backend

        try:
            (useroverrides, truncated) = ldap.find_entries(
                filter="objectclass=ipaUserOverride",
                attrs_list=['ipaanchoruuid'],
                base_dn=dn,
                scope=ldap.SCOPE_ONELEVEL,
                paged_search=True)

            entry_attrs['useroverrides'] = [
                view.single_value.get('ipaanchoruuid')
                for view in useroverrides
            ]

        except errors.NotFound:
            pass

        try:
            (groupoverrides, truncated) = ldap.find_entries(
                filter="objectclass=ipaGroupOverride",
                attrs_list=['ipaanchoruuid'],
                base_dn=dn,
                scope=ldap.SCOPE_ONELEVEL,
                paged_search=True)

            entry_attrs['groupoverrides'] = [
                view.single_value.get('ipaanchoruuid')
                for view in groupoverrides
            ]

        except errors.NotFound:
            pass

    def enumerate_hosts(self, dn, entry_attrs):
        ldap = self.obj.backend

        filter_params = {
            'ipaAssignedIDView': dn,
            'objectClass': 'ipaHost',
        }

        try:
            (hosts, truncated) = ldap.find_entries(
                filter=ldap.make_filter(filter_params, rules=ldap.MATCH_ALL),
                attrs_list=['cn'],
                base_dn=api.env.container_host + api.env.basedn,
                scope=ldap.SCOPE_ONELEVEL,
                paged_search=True)

            entry_attrs['appliedtohosts'] = [host.single_value['cn']
                                             for host in hosts]
        except errors.NotFound:
            pass

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.show_id_overrides(dn, entry_attrs)

        if options.get('show_hosts', False):
            self.enumerate_hosts(dn, entry_attrs)

        return dn


class baseidview_apply(LDAPQuery):
    """
    Base class for idview_apply and idview_unapply commands.
    """

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        view = keys[-1] if keys else None
        ldap = self.obj.backend

        # Test if idview actually exists, if it does not, NotFound is raised
        if not options.get('clear_view', False):
            view_dn = self.api.Object['idview'].get_dn_if_exists(view)
            assert isinstance(view_dn, DN)
        else:
            # In case we are removing assigned view, we modify the host setting
            # the ipaAssignedIDView to None
            view_dn = None

        completed = 0
        succeeded = {'host': []}
        failed = {
            'host': [],
            'hostgroup': [],
            }

        # Generate a list of all hosts to apply the view to
        hosts_to_apply = list(options.get('host', []))

        for hostgroup in options.get('hostgroup', ()):
            try:
                hosts_to_apply += get_complete_hostgroup_member_list(hostgroup)
            except errors.NotFound:
                failed['hostgroup'].append((hostgroup, "not found"))
            except errors.PublicError as e:
                failed['hostgroup'].append((hostgroup, "%s : %s" % (
                                            e.__class__.__name__, str(e))))

        for host in hosts_to_apply:
            try:
                host_dn = api.Object['host'].get_dn_if_exists(host)

                host_entry = ldap.get_entry(host_dn,
                                            attrs_list=['ipaassignedidview'])
                host_entry['ipaassignedidview'] = view_dn

                ldap.update_entry(host_entry)

                # If no exception was raised, view assigment went well
                completed = completed + 1
                succeeded['host'].append(host)
            except errors.EmptyModlist:
                # If view was already applied, do not complain
                pass
            except errors.NotFound:
                failed['host'].append((host, "not found"))
            except errors.PublicError as e:
                failed['host'].append((host, str(e)))

        # Wrap dictionary containing failures in another dictionary under key
        # 'memberhost', since that is output parameter in global_output_params
        # and thus we get nice output in the CLI
        failed = {'memberhost': failed}

        # Sort the list of affected hosts
        succeeded['host'].sort()

        # Note that we're returning the list of affected hosts even if they
        # were passed via referencing a hostgroup. This is desired, since we
        # want to stress the fact that view is applied on all the current
        # member hosts of the hostgroup and not tied with the hostgroup itself.

        return dict(
            summary=unicode(_(self.msg_summary % {'value': view})),
            succeeded=succeeded,
            completed=completed,
            failed=failed,
        )


@register()
class idview_apply(baseidview_apply):
    __doc__ = _('Applies ID view to specified hosts or current members of '
                'specified hostgroups. If any other ID view is applied to '
                'the host, it is overriden.')

    member_count_out = (_('ID view applied to %i host.'),
                        _('ID view applied to %i hosts.'))

    msg_summary = 'Applied ID view "%(value)s"'

    takes_options = (
        Str('host*',
            cli_name='hosts',
            doc=_('Hosts to apply the ID view to'),
            label=_('hosts'),
        ),
        Str('hostgroup*',
            cli_name='hostgroups',
            doc=_('Hostgroups to whose hosts apply the ID view to. Please note '
                  'that view is not applied automatically to any hosts added '
                  'to the hostgroup after running the idview-apply command.'),
            label=_('hostgroups'),
        ),
    )

    has_output = (
        output.summary,
        output.Output('succeeded',
            type=dict,
            doc=_('Hosts that this ID view was applied to.'),
        ),
        output.Output('failed',
            type=dict,
            doc=_('Hosts or hostgroups that this ID view could not be '
                  'applied to.'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of hosts the ID view was applied to:'),
        ),
    )


@register()
class idview_unapply(baseidview_apply):
    __doc__ = _('Clears ID view from specified hosts or current members of '
                'specified hostgroups.')

    member_count_out = (_('ID view cleared from %i host.'),
                        _('ID view cleared from %i hosts.'))

    msg_summary = 'Cleared ID views'

    takes_options = (
        Str('host*',
            cli_name='hosts',
            doc=_('Hosts to clear (any) ID view from.'),
            label=_('hosts'),
        ),
        Str('hostgroup*',
            cli_name='hostgroups',
            doc=_('Hostgroups whose hosts should have ID views cleared. Note '
                  'that view is not cleared automatically from any host added '
                  'to the hostgroup after running idview-unapply command.'),
            label=_('hostgroups'),
        ),
    )

    has_output = (
        output.summary,
        output.Output('succeeded',
            type=dict,
            doc=_('Hosts that ID view was cleared from.'),
        ),
        output.Output('failed',
            type=dict,
            doc=_('Hosts or hostgroups that ID view could not be cleared '
                  'from.'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of hosts that had a ID view was unset:'),
        ),
    )

    # Take no arguments, since ID View reference is not needed to clear
    # the hosts
    def get_args(self):
        return ()

    def execute(self, *keys, **options):
        options['clear_view'] = True
        return super(idview_unapply, self).execute(*keys, **options)


# This is not registered on purpose, it's a base class for ID overrides
class baseidoverride(LDAPObject):
    """
    Base ID override object.
    """

    parent_object = 'idview'
    container_dn = api.env.container_views

    object_class = ['ipaOverrideAnchor', 'top']
    default_attributes = [
       'description', 'ipaAnchorUUID',
    ]

    takes_params = (
        Str('ipaanchoruuid',
            cli_name='anchor',
            primary_key=True,
            label=_('Anchor to override'),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
        ),
    )

    override_object = None

    def resolve_object_to_anchor(self, obj):
        """
        Resolves the user/group name to the anchor uuid:
            - first it tries to find the object as user in IPA
            - then it tries to find the object as group in IPA
            - if the IPA lookups both failed, use SSSD to lookup object SID in
              the trusted domains
        """

        # First try to resolve the object as IPA user or group
        for obj_type in ('user', 'group'):
            try:
                entry = self.backend.get_entry(api.Object[obj_type].get_dn(obj),
                                               attrs_list=['ipaUniqueID'])
                return IPA_ANCHOR_PREFIX + entry.single_value.get('ipaUniqueID')
            except errors.NotFound:
                pass

        # If not successfull, try looking up the object in the trusted domain
        if _dcerpc_bindings_installed:
            domain_validator = ipaserver.dcerpc.DomainValidator(api)
            if domain_validator.is_configured():
                sid = domain_validator.get_trusted_domain_object_sid(obj)
                return SID_ANCHOR_PREFIX + sid

    def resolve_anchor_to_object_name(self, anchor):
        if anchor.startswith(IPA_ANCHOR_PREFIX):
            uuid = anchor.split(IPA_ANCHOR_PREFIX)[1].strip()

            # Prepare search parameters
            accounts_dn = DN(api.env.container_accounts, api.env.basedn)
            class_filter = self.backend.make_filter_from_attr(
                               attr='objectClass',
                               value=['posixaccount','ipausergroup'])

            uuid_filter = self.backend.make_filter_from_attr(
                               attr='ipaUniqueID',
                               value=uuid)

            # We need to filter for any object with above objectclasses
            # AND specified UUID
            object_filter = self.backend.combine_filters(
                                [class_filter, uuid_filter],
                                self.backend.MATCH_ALL)

            entries, truncated = self.backend.find_entries(
                                     filter=object_filter,
                                     attrs_list=['cn','uid'],
                                     base_dn=accounts_dn)

            # Handle incorrect number of results. Should not happen
            # since UUID stands for UniqueUID.

            if len(entries) > 1:
                raise errors.SingleMatchExpected(found=len(entries))
            else:
                if truncated:
                    raise errors.LimitsExceeded()
                else:
                    # Return the name of the object, which is either cn for
                    # groups or uid for users
                    return (entries[0].single_value.get('uid') or
                            entries[0].single_value.get('cn'))

        elif anchor.startswith(SID_ANCHOR_PREFIX):
            sid = anchor.split(SID_ANCHOR_PREFIX)[1].strip()

            if _dcerpc_bindings_installed:
                domain_validator = ipaserver.dcerpc.DomainValidator(api)
                if domain_validator.is_configured():
                    name = domain_validator.get_trusted_domain_object_from_sid(sid)
                    return name


    def get_dn(self, *keys, **options):
        keys = keys[:-1] + (self.resolve_object_to_anchor(keys[-1]), )
        return super(idoverride, self).get_dn(*keys, **options)

    def set_anchoruuid_from_dn(self, dn, entry_attrs):
        # TODO: Use entry_attrs.single_value once LDAPUpdate supports
        # lists in primary key fields (baseldap.LDAPUpdate.execute)
        entry_attrs['ipaanchoruuid'] = dn[0].value

    def convert_anchor_to_human_readable_form(self, entry_attrs, **options):
        if not options.get('raw'):
            anchor = entry_attrs.single_value.get('ipaanchoruuid')

            if anchor:
                object_name = self.resolve_anchor_to_object_name(anchor)
                entry_attrs.single_value['ipaanchoruuid'] = object_name

@register()
class idoverride_add(LDAPCreate):
    __doc__ = _('Add a new ID override.')
    msg_summary = _('Added ID override "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.obj.set_anchoruuid_from_dn(dn, entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_anchor_to_human_readable_form(entry_attrs, **options)
        return dn


@register()
class idoverride_del(LDAPDelete):
    __doc__ = _('Delete an ID override.')
    msg_summary = _('Deleted ID override "%(value)s"')


@register()
class idoverride_mod(LDAPUpdate):
    __doc__ = _('Modify an ID override.')
    msg_summary = _('Modified an ID override "%(value)s"')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_anchor_to_human_readable_form(entry_attrs, **options)
        return dn


@register()
class idoverride_find(LDAPSearch):
    __doc__ = _('Search for an ID override.')
    msg_summary = ngettext('%(count)d ID override matched',
                           '%(count)d ID overrides matched', 0)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry in entries:
            self.obj.convert_anchor_to_human_readable_form(entry, **options)
        return truncated


@register()
class idoverride_show(LDAPRetrieve):
    __doc__ = _('Display information about an ID override.')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_anchor_to_human_readable_form(entry_attrs, **options)
        return dn


@register()
class idoverrideuser(baseidoverride):

    object_name = _('User ID override')
    object_name_plural = _('User ID overrides')

    label = _('User ID overrides')
    label_singular = _('User ID override')
    rdn_is_primary_key = True

    permission_filter_objectclasses = ['ipaUserOverride']
    managed_permissions = {
        'System: Read User ID Overrides': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectClass', 'ipaAnchorUUID', 'uidNumber', 'description',
                'homeDirectory', 'uid',
            },
        },
    }

    object_class = baseidoverride.object_class + ['ipaUserOverride']
    default_attributes = baseidoverride.default_attributes + [
       'homeDirectory', 'uidNumber', 'uid',
    ]

    takes_params = baseidoverride.takes_params + (
        Str('uid?',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='login',
            label=_('User login'),
            normalizer=lambda value: value.lower(),
        ),
        Int('uidnumber?',
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number'),
            minvalue=1,
        ),
        Str('homedirectory?',
            cli_name='homedir',
            label=_('Home directory'),
        ),
    )

    override_object = 'user'


@register()
class idoverridegroup(baseidoverride):

    object_name = _('Group ID override')
    object_name_plural = _('Group ID overrides')

    label = _('Group ID overrides')
    label_singular = _('Group ID override')
    rdn_is_primary_key = True

    permission_filter_objectclasses = ['ipaGroupOverride']
    managed_permissions = {
        'System: Read Group ID Overrides': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectClass', 'ipaAnchorUUID', 'gidNumber',
                'description', 'cn',
            },
        },
    }

    object_class = baseidoverride.object_class + ['ipaGroupOverride']
    default_attributes = baseidoverride.default_attributes + [
       'gidNumber', 'cn',
    ]

    takes_params = baseidoverride.takes_params + (
        Str('cn?',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='group_name',
            label=_('Group name'),
            normalizer=lambda value: value.lower(),
        ),
        Int('gidnumber?',
            cli_name='gid',
            label=_('GID'),
            doc=_('Group ID Number'),
            minvalue=1,
        ),
    )

    override_object = 'group'
