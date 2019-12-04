#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import (
    absolute_import,
    division,
)

from ipalib import (
    _,
    ngettext,
    api,
    Str,
    DNSNameParam,
    output,
    messages
)
from ipalib.errors import DependentEntry
from ipalib.plugable import Registry
from ipaserver.dns_data_management import IPASystemRecords
from ipaserver.plugins.baseldap import (
    LDAPCreate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPDelete,
    LDAPObject,
    LDAPUpdate,
)
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

__doc__ = _("""
IPA locations
""") + _("""
Manipulate DNS locations
""") + _("""
EXAMPLES:
""") + _("""
  Find all locations:
    ipa location-find
""") + _("""
  Show specific location:
    ipa location-show location
""") + _("""
  Add location:
    ipa location-add location --description 'My location'
""") + _("""
  Delete location:
    ipa location-del location
""")

register = Registry()


@register()
class location(LDAPObject):
    """
    IPA locations
    """
    container_dn = api.env.container_locations
    object_name = _('location')
    object_name_plural = _('locations')
    object_class = ['top', 'ipaLocationObject']
    search_attributes = ['idnsName']
    default_attributes = [
        'idnsname', 'description'
    ]
    label = _('IPA Locations')
    label_singular = _('IPA Location')

    permission_filter_objectclasses = ['ipaLocationObject']
    managed_permissions = {
        'System: Read IPA Locations': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'idnsname', 'description',
            },
            'default_privileges': {'DNS Administrators'},
        },
        'System: Add IPA Locations': {
            'ipapermright': {'add'},
            'default_privileges': {'DNS Administrators'},
        },
        'System: Remove IPA Locations': {
            'ipapermright': {'delete'},
            'default_privileges': {'DNS Administrators'},
        },
        'System: Modify IPA Locations': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'description',
            },
            'default_privileges': {'DNS Administrators'},
        },
    }

    takes_params = (
        DNSNameParam(
            'idnsname',
            cli_name='name',
            primary_key=True,
            label=_('Location name'),
            doc=_('IPA location name'),
            # dns name must be relative, we will put it into middle of
            # location domain name for location records
            only_relative=True,
        ),
        Str(
            'description?',
            label=_('Description'),
            doc=_('IPA Location description'),
        ),
        Str(
            'servers_server*',
            label=_('Servers'),
            doc=_('Servers that belongs to the IPA location'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'dns_server*',
            label=_('Advertised by servers'),
            doc=_('List of servers which advertise the given location'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
    )

    def get_dn(self, *keys, **options):
        loc = keys[0]
        assert isinstance(loc, DNSName)
        loc_a = loc.ToASCII()

        return super(location, self).get_dn(loc_a, **options)


@register()
class location_add(LDAPCreate):
    __doc__ = _('Add a new IPA location.')

    msg_summary = _('Added IPA location "%(value)s"')


@register()
class location_del(LDAPDelete):
    __doc__ = _('Delete an IPA location.')

    msg_summary = _('Deleted IPA location "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        if not options.get('force'):
            servers = self.api.Command.server_find(
                in_location=keys[-1])['result']
            location_member = servers[0]['cn'][0] if servers else None
            if location_member:
                raise DependentEntry(
                    label=_('IPA Server'),
                    key=keys[-1],
                    dependent=location_member
                )
        system_records =IPASystemRecords(self.api)
        _success, failed = system_records.remove_location_records(keys[-1])
        if failed:
            self.add_message(messages.AutomaticDNSRecordsUpdateFailed())
        return dn


@register()
class location_mod(LDAPUpdate):
    __doc__ = _('Modify information about an IPA location.')

    msg_summary = _('Modified IPA location "%(value)s"')


@register()
class location_find(LDAPSearch):
    __doc__ = _('Search for IPA locations.')

    msg_summary = ngettext(
        '%(count)d IPA location matched',
        '%(count)d IPA locations matched', 0
    )


@register()
class location_show(LDAPRetrieve):
    __doc__ = _('Display information about an IPA location.')

    has_output = LDAPRetrieve.has_output + (
        output.Output(
            'servers',
            type=dict,
            doc=_('Servers in location'),
            flags={'no_display'},  # we use customized print to CLI
        ),
    )

    def execute(self, *keys, **options):
        result = super(location_show, self).execute(*keys, **options)

        servers_additional_info = {}
        if not options.get('raw'):
            servers_name = []
            dns_servers = []
            weight_sum = 0

            servers = self.api.Command.server_find(
                in_location=keys[0], no_members=False)['result']
            for server in servers:
                s_name = server['cn'][0]
                servers_name.append(s_name)
                weight = int(server.get('ipaserviceweight', [100])[0])
                weight_sum += weight
                servers_additional_info[s_name] = {
                    'cn': server['cn'],
                    'ipaserviceweight': server.get(
                        'ipaserviceweight', [u'100']),
                }

                s_roles = server.get('enabled_role_servrole', ())
                if s_roles:
                    servers_additional_info[s_name][
                        'enabled_role_servrole'] = s_roles
                if 'DNS server' in s_roles:
                    dns_servers.append(s_name)

            for server in servers_additional_info.values():
                if weight_sum != 0:
                    server['service_relative_weight'] = [
                        u'{:.1f}%'.format(
                            int(server['ipaserviceweight'][0]) * 100.0 /
                            weight_sum
                        )
                    ]
                else:
                    server['service_relative_weight'] = [
                        u'{:.1f}%'.format(int(100.0 / len(servers)))
                    ]
            if servers_name:
                result['result']['servers_server'] = servers_name

            if dns_servers:
                result['result']['dns_server'] = dns_servers

            if not dns_servers and servers_additional_info:
                self.add_message(messages.LocationWithoutDNSServer(
                    location=keys[0]
                ))

        result['servers'] = servers_additional_info

        return result
