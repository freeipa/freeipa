#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import string
import os

import dbus
import dbus.mainloop.glib

from ipalib import api, crud, errors, messages
from ipalib import Int, Str
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import *
from ipalib.plugins import baseldap
from ipalib.request import context
from ipalib import _, ngettext

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
    search_attributes = ['cn']
    default_attributes = [
        'cn', 'iparepltopomanagedsuffix', 'ipamindomainlevel',
        'ipamaxdomainlevel'
    ]
    label = _('IPA Servers')
    label_singular = _('IPA Server')
    attribute_members = {
        'iparepltopomanagedsuffix': ['topologysuffix'],
    }
    relationships = {
        'iparepltopomanagedsuffix': ('Managed', '', 'no_'),
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


@register()
class server_find(LDAPSearch):
    __doc__ = _('Search for IPA servers.')

    msg_summary = ngettext(
        '%(count)d IPA server matched',
        '%(count)d IPA servers matched', 0
    )
    member_attributes = ['iparepltopomanagedsuffix']

    def get_options(self):
        for option in super(server_find, self).get_options():
            if option.name == 'topologysuffix':
                option = option.clone(cli_name='topologysuffixes')
            elif option.name == 'no_topologysuffix':
                option = option.clone(cli_name='no_topologysuffixes')
            yield option

    def get_member_filter(self, ldap, **options):
        options.pop('topologysuffix', None)
        options.pop('no_topologysuffix', None)

        return super(server_find, self).get_member_filter(ldap, **options)

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

        return (filters, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if not options.get('raw', False):
            suffixes = self.obj._get_suffixes()
            for entry in entries:
                self.obj._apply_suffixes(entry, suffixes)

        return truncated


@register()
class server_show(LDAPRetrieve):
    __doc__ = _('Show IPA server.')

    def post_callback(self, ldap, dn, entry, *keys, **options):
        if not options.get('raw', False):
            suffixes = self.obj._get_suffixes()
            self.obj._apply_suffixes(entry, suffixes)

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
        filter = ldap.make_filter(
            {'krbprincipalname': context.principal, 'memberof': privilege_dn},
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
