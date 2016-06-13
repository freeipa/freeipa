#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import dbus
import dbus.mainloop.glib

from ipalib import api, crud, errors, messages
from ipalib import Int, Str, DNSNameParam
from ipalib.plugable import Registry
from .baseldap import (
    LDAPSearch,
    LDAPRetrieve,
    LDAPDelete,
    LDAPObject,
    LDAPUpdate,
)
from ipalib.request import context
from ipalib import _, ngettext
from ipalib import output
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipaserver.servroles import ENABLED

__doc__ = _("""
IPA servers
""") + _("""
Get information about installed IPA servers.
""") + _("""
EXAMPLES:
""") + _("""
  Find all servers:
    ipa server-find
""") + _("""
  Show specific server:
    ipa server-show ipa.example.com
""")

register = Registry()


@register()
class server(LDAPObject):
    """
    IPA server
    """
    container_dn = api.env.container_masters
    object_name = _('server')
    object_name_plural = _('servers')
    object_class = ['top']
    possible_objectclasses = ['ipaLocationMember']
    search_attributes = ['cn']
    default_attributes = [
        'cn', 'iparepltopomanagedsuffix', 'ipamindomainlevel',
        'ipamaxdomainlevel', 'ipalocation', 'ipalocationweight'
    ]
    label = _('IPA Servers')
    label_singular = _('IPA Server')
    attribute_members = {
        'iparepltopomanagedsuffix': ['topologysuffix'],
        'ipalocation': ['location'],
        'role': ['servrole'],
    }
    relationships = {
        'iparepltopomanagedsuffix': ('Managed', '', 'no_'),
        'ipalocation': ('IPA', 'in_', 'not_in_'),
        'role': ('Enabled', '', 'no_'),
    }
    permission_filter_objectclasses = ['ipaConfigObject']
    managed_permissions = {
        'System: Read Locations of IPA Servers': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'ipalocation', 'ipalocationweight',
            },
            'default_privileges': {'DNS Administrators'},
        },
        'System: Read Status of Services on IPA Servers': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {'objectclass', 'cn', 'ipaconfigstring'},
            'default_privileges': {'DNS Administrators'},
        }
    }

    takes_params = (
        Str(
            'cn',
            cli_name='name',
            primary_key=True,
            label=_('Server name'),
            doc=_('IPA server hostname'),
        ),
        Str(
            'iparepltopomanagedsuffix*',
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'iparepltopomanagedsuffix_topologysuffix*',
            label=_('Managed suffixes'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Int(
            'ipamindomainlevel',
            cli_name='minlevel',
            label=_('Min domain level'),
            doc=_('Minimum domain level'),
            flags={'no_create', 'no_update'},
        ),
        Int(
            'ipamaxdomainlevel',
            cli_name='maxlevel',
            label=_('Max domain level'),
            doc=_('Maximum domain level'),
            flags={'no_create', 'no_update'},
        ),
        DNSNameParam(
            'ipalocation_location?',
            cli_name='location',
            label=_('Location'),
            doc=_('Server location'),
            only_relative=True,
            flags={'no_search'},
        ),
        Int(
            'ipalocationweight?',
            cli_name='location_weight',
            label=_('Location weight'),
            doc=_('Location weight for server'),
            minvalue=0,
            maxvalue=65535,
            flags={'no_search'},
        ),
        Str(
            'location_relative_weight',
            label=_('Location relative weight'),
            doc=_('Location relative weight for server (counts per location)'),
            flags={'virtual_attribute','no_create', 'no_update', 'no_search'},
        ),
        Str(
            'enabled_role_servrole*',
            label=_('Enabled server roles'),
            doc=_('List of enabled roles'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'}
        ),
    )

    def _get_suffixes(self):
        suffixes = self.api.Command.topologysuffix_find(
            all=True, raw=True,
        )['result']
        suffixes = [(s['iparepltopoconfroot'][0], s['dn']) for s in suffixes]
        return suffixes

    def _apply_suffixes(self, entry, suffixes):
        # change suffix DNs to topologysuffix entry DNs
        # this fixes LDAPObject.convert_attribute_members() for suffixes
        suffixes = dict(suffixes)
        if 'iparepltopomanagedsuffix' in entry:
            entry['iparepltopomanagedsuffix'] = [
                suffixes.get(m, m) for m in entry['iparepltopomanagedsuffix']
            ]

    def normalize_location(self, kw, **options):
        """
        Return the DN of location
        """
        if 'ipalocation_location' in kw:
            location = kw.pop('ipalocation_location')
            kw['ipalocation'] = (
                [self.api.Object.location.get_dn(location)]
                if location is not None else location
            )

    def convert_location(self, entry_attrs, **options):
        """
        Return a location name from DN
        """
        if options.get('raw'):
            return

        converted_locations = [
            DNSName(location_dn['idnsname']) for
            location_dn in entry_attrs.pop('ipalocation', [])
        ]

        if converted_locations:
            entry_attrs['ipalocation_location'] = converted_locations

    def get_enabled_roles(self, entry_attrs, **options):
        if options.get('raw', False) or options.get('no_members', False):
            return

        enabled_roles = self.api.Command.server_role_find(
            server_server=entry_attrs['cn'][0], status=ENABLED)['result']

        enabled_role_names = [r[u'role_servrole'] for r in enabled_roles]

        entry_attrs['enabled_role_servrole'] = enabled_role_names


@register()
class server_mod(LDAPUpdate):
    __doc__ = _('Modify information about an IPA server.')

    msg_summary = _('Modified IPA server "%(value)s"')

    def args_options_2_entry(self, *args, **options):
        kw = super(server_mod, self).args_options_2_entry(
            *args, **options)
        self.obj.normalize_location(kw, **options)
        return kw

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        if entry_attrs.get('ipalocation'):
            if not ldap.entry_exists(entry_attrs['ipalocation'][0]):
                self.api.Object.location.handle_not_found(
                    options['ipalocation_location'])

        if 'ipalocation' or 'ipalocationweight' in entry_attrs:
            server_entry = ldap.get_entry(dn, ['objectclass'])

            # we need to extend object with ipaLocationMember objectclass
            entry_attrs['objectclass'] = (
                server_entry['objectclass'] + ['ipalocationmember']
            )

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.get_enabled_roles(entry_attrs)

        if 'ipalocation' or 'ipalocationweight' in entry_attrs:
            result = self.api.Command.dns_update_system_records()
            if not result.get('value'):
                self.add_message(messages.AutomaticDNSRecordsUpdateFailed())
        self.obj.convert_location(entry_attrs, **options)

        return dn


@register()
class server_find(LDAPSearch):
    __doc__ = _('Search for IPA servers.')

    msg_summary = ngettext(
        '%(count)d IPA server matched',
        '%(count)d IPA servers matched', 0
    )

    member_attributes = ['iparepltopomanagedsuffix', 'ipalocation', 'role']

    def args_options_2_entry(self, *args, **options):
        kw = super(server_find, self).args_options_2_entry(
            *args, **options)
        self.obj.normalize_location(kw, **options)
        return kw

    def get_options(self):
        for option in super(server_find, self).get_options():
            if option.name == 'topologysuffix':
                option = option.clone(cli_name='topologysuffixes')
            elif option.name == 'no_topologysuffix':
                option = option.clone(cli_name='no_topologysuffixes')
            # we do not want to test negative membership for roles
            elif option.name == 'no_servrole':
                continue
            yield option

    def get_member_filter(self, ldap, **options):
        options.pop('topologysuffix', None)
        options.pop('no_topologysuffix', None)

        options.pop('servrole', None)

        return super(server_find, self).get_member_filter(
            ldap, **options)

    def _get_enabled_servrole_filter(self, ldap, servroles):
        """
        return a filter matching any master which has all the specified roles
        enabled.
        """
        def _get_masters_with_enabled_servrole(role):
            role_status = self.api.Command.server_role_find(
                server_server=None,
                role_servrole=role,
                status=ENABLED)['result']

            return set(
                r[u'server_server'] for r in role_status)

        enabled_masters = _get_masters_with_enabled_servrole(
            servroles[0])

        for role in servroles[1:]:
            enabled_masters.intersection_update(
                _get_masters_with_enabled_servrole(role)
            )

        if not enabled_masters:
            return '(!(objectclass=*))'

        return ldap.make_filter_from_attr(
            'cn',
            list(enabled_masters),
            rules=ldap.MATCH_ANY
        )

    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope,
                     *args, **options):
        included = options.get('topologysuffix')
        excluded = options.get('no_topologysuffix')

        if included or excluded:
            topologysuffix = self.api.Object.topologysuffix
            suffixes = self.obj._get_suffixes()
            suffixes = {s[1]: s[0] for s in suffixes}

            if included:
                included = [topologysuffix.get_dn(pk) for pk in included]
                try:
                    included = [suffixes[dn] for dn in included]
                except KeyError:
                    # force empty result
                    filter = '(!(objectclass=*))'
                else:
                    filter = ldap.make_filter_from_attr(
                        'iparepltopomanagedsuffix', included, ldap.MATCH_ALL
                    )
                filters = ldap.combine_filters(
                    (filters, filter), ldap.MATCH_ALL
                )

            if excluded:
                excluded = [topologysuffix.get_dn(pk) for pk in excluded]
                excluded = [suffixes[dn] for dn in excluded if dn in suffixes]
                filter = ldap.make_filter_from_attr(
                    'iparepltopomanagedsuffix', excluded, ldap.MATCH_NONE
                )
                filters = ldap.combine_filters(
                    (filters, filter), ldap.MATCH_ALL
                )

        if options.get('servrole', []):
            servrole_filter = self._get_enabled_servrole_filter(
                ldap, options['servrole'])
            filters = ldap.combine_filters(
                (filters, servrole_filter), ldap.MATCH_ALL)

        return (filters, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if not options.get('raw', False):
            suffixes = self.obj._get_suffixes()
            for entry in entries:
                self.obj._apply_suffixes(entry, suffixes)

        for entry in entries:
            self.obj.convert_location(entry, **options)
            self.obj.get_enabled_roles(entry, **options)
        return truncated


@register()
class server_show(LDAPRetrieve):
    __doc__ = _('Show IPA server.')

    def post_callback(self, ldap, dn, entry, *keys, **options):
        if not options.get('raw', False):
            suffixes = self.obj._get_suffixes()
            self.obj._apply_suffixes(entry, suffixes)

        self.obj.convert_location(entry, **options)
        self.obj.get_enabled_roles(entry, **options)

        return dn


@register()
class server_del(LDAPDelete):
    __doc__ = _('Delete IPA server.')
    NO_CLI = True
    msg_summary = _('Deleted IPA server "%(value)s"')


@register()
class server_conncheck(crud.PKQuery):
    __doc__ = _("Check connection to remote IPA server.")

    NO_CLI = True

    takes_args = (
        Str(
            'remote_cn',
            cli_name='remote_name',
            label=_('Remote server name'),
            doc=_('Remote IPA server hostname'),
        ),
    )

    has_output = output.standard_value

    def execute(self, *keys, **options):
        # the server must be the local host
        if keys[-2] != api.env.host:
            raise errors.ValidationError(
                name='cn', error=_("must be \"%s\"") % api.env.host)

        # the server entry must exist
        try:
            self.obj.get_dn_if_exists(*keys[:-1])
        except errors.NotFound:
            self.obj.handle_not_found(keys[-2])

        # the user must have the Replication Administrators privilege
        privilege = u'Replication Administrators'
        privilege_dn = self.api.Object.privilege.get_dn(privilege)
        ldap = self.obj.backend
        filter = ldap.make_filter({
            'krbprincipalname': context.principal,  # pylint: disable=no-member
            'memberof': privilege_dn},
            rules=ldap.MATCH_ALL)
        try:
            ldap.find_entries(base_dn=self.api.env.basedn, filter=filter)
        except errors.NotFound:
            raise errors.ACIError(
                info=_("not allowed to perform server connection check"))

        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

        bus = dbus.SystemBus()
        obj = bus.get_object('org.freeipa.server', '/',
                             follow_name_owner_changes=True)
        server = dbus.Interface(obj, 'org.freeipa.server')

        ret, stdout, stderr = server.conncheck(keys[-1])

        result = dict(
            result=(ret == 0),
            value=keys[-2],
        )

        for line in stdout.splitlines():
            messages.add_message(options['version'],
                                 result,
                                 messages.ExternalCommandOutput(line=line))

        return result
