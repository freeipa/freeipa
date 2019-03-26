#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging

import dbus
import dbus.mainloop.glib
import ldap
import time

from ipalib import api, crud, errors, messages
from ipalib import Int, Flag, Str, StrEnum, DNSNameParam
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
from ipaplatform import services
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipaserver import topology
from ipaserver.servroles import ENABLED, HIDDEN
from ipaserver.install import bindinstance, dnskeysyncinstance
from ipaserver.install.service import hide_services, enable_services

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

logger = logging.getLogger(__name__)

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
        'ipamaxdomainlevel', 'ipalocation', 'ipaserviceweight'
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
                'objectclass', 'cn', 'ipalocation', 'ipaserviceweight',
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
            'ipaserviceweight?',
            cli_name='service_weight',
            label=_('Service weight'),
            doc=_('Weight for server services'),
            minvalue=0,
            maxvalue=65535,
            flags={'no_search'},
        ),
        Str(
            'service_relative_weight',
            label=_('Service relative weight'),
            doc=_('Relative weight for server services (counts per location)'),
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
        if not options.get('all', False) and options.get('no_members', False):
            return

        if options.get('raw', False):
            return

        enabled_roles = self.api.Command.server_role_find(
            server_server=entry_attrs['cn'][0],
            status=ENABLED,
            include_master=True,
        )['result']

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
                raise self.api.Object.location.handle_not_found(
                    options['ipalocation_location'])

        if 'ipalocation' in entry_attrs or 'ipaserviceweight' in entry_attrs:
            server_entry = ldap.get_entry(dn, ['objectclass'])

            # we need to extend object with ipaLocationMember objectclass
            entry_attrs['objectclass'] = (
                server_entry['objectclass'] + ['ipalocationmember']
            )

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.get_enabled_roles(entry_attrs)

        if 'ipalocation_location' in options:
            ipalocation = entry_attrs.get('ipalocation')
            if ipalocation:
                ipalocation = ipalocation[0]['idnsname']
            else:
                ipalocation = u''
            try:
                self.api.Command.dnsserver_mod(
                    keys[0],
                    setattr=[
                        u'idnsSubstitutionVariable;ipalocation={loc}'.format(
                            loc=ipalocation)
                    ]
                )
            except errors.EmptyModlist:
                pass
            except errors.NotFound:
                # server is not DNS server
                pass

        if 'ipalocation_location' or 'ipaserviceweight' in options:
            self.add_message(messages.ServiceRestartRequired(
                service=services.service('named', api).systemd_name,
                server=keys[0], ))

            result = self.api.Command.dns_update_system_records()
            if not result.get('value'):
                self.add_message(messages.AutomaticDNSRecordsUpdateFailed())
        self.obj.convert_location(entry_attrs, **options)

        ipalocation = entry_attrs.get('ipalocation_location', [None])[0]
        if ipalocation:
            servers_in_loc = self.api.Command.server_find(
                in_location=ipalocation, no_members=False)['result']
            dns_server_in_loc = False
            for server in servers_in_loc:
                if 'DNS server' in server.get('enabled_role_servrole', ()):
                    dns_server_in_loc = True
                    break
            if not dns_server_in_loc:
                self.add_message(messages.LocationWithoutDNSServer(
                    location=ipalocation
                ))

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
                status=ENABLED,
                include_master=True,
            )['result']

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
    msg_summary = _('Deleted IPA server "%(value)s"')

    takes_options = LDAPDelete.takes_options + (
        Flag(
            'ignore_topology_disconnect?',
            label=_('Ignore topology errors'),
            doc=_('Ignore topology connectivity problems after removal'),
            default=False,
        ),
        Flag(
            'ignore_last_of_role?',
            label=_('Ignore check for last remaining CA or DNS server'),
            doc=_('Skip a check whether the last CA master or DNS server is '
                  'removed'),
            default=False,
        ),
        Flag(
            'force?',
            label=_('Force server removal'),
            doc=_('Force server removal even if it does not exist'),
            default=False,
        ),
    )

    def _ensure_last_of_role(self, hostname, ignore_last_of_role=False):
        """
        1. When deleting server, check if there will be at least one remaining
           DNS and CA server.
        2. Pick CA renewal master
        """
        def handler(msg, ignore_last_of_role):
            if ignore_last_of_role:
                self.add_message(
                    messages.ServerRemovalWarning(
                        message=msg
                    )
                )
            else:
                raise errors.ServerRemovalError(reason=_(msg))

        ipa_config = self.api.Command.config_show()['result']

        ipa_masters = ipa_config['ipa_master_server']

        # skip these checks if the last master is being removed
        if len(ipa_masters) <= 1:
            return

        if self.api.Command.dns_is_enabled()['result']:
            dns_config = self.api.Command.dnsconfig_show()['result']

            dns_servers = dns_config.get('dns_server_server', [])
            dnssec_keymaster = dns_config.get('dnssec_key_master_server', [])

            if dnssec_keymaster == hostname:
                handler(
                    _("Replica is active DNSSEC key master. Uninstall "
                      "could break your DNS system. Please disable or "
                      "replace DNSSEC key master first."), ignore_last_of_role)

            if dns_servers == [hostname]:
                handler(
                    _("Deleting this server will leave your installation "
                      "without a DNS."), ignore_last_of_role)

        if self.api.Command.ca_is_enabled()['result']:
            try:
                vault_config = self.api.Command.vaultconfig_show()['result']
                kra_servers = vault_config.get('kra_server_server', [])
            except errors.InvocationError:
                # KRA is not configured
                pass
            else:
                if kra_servers == [hostname]:
                    handler(
                        _("Deleting this server is not allowed as it would "
                          "leave your installation without a KRA."),
                        ignore_last_of_role)

            ca_servers = ipa_config.get('ca_server_server', [])
            ca_renewal_master = ipa_config.get(
                'ca_renewal_master_server', [])

            if ca_servers == [hostname]:
                handler(
                    _("Deleting this server is not allowed as it would "
                      "leave your installation without a CA."),
                    ignore_last_of_role)

            # change the renewal master if there is other master with CA
            if ca_renewal_master == hostname:
                other_cas = [ca for ca in ca_servers if ca != hostname]

                if other_cas:
                    self.api.Command.config_mod(
                        ca_renewal_master_server=other_cas[0])

        if ignore_last_of_role:
            self.add_message(
                messages.ServerRemovalWarning(
                    message=_("Ignoring these warnings and proceeding with "
                              "removal")))

    def _check_topology_connectivity(self, topology_connectivity, master_cn):
        try:
            topology_connectivity.check_current_state()
        except ValueError as e:
            raise errors.ServerRemovalError(reason=e)

        try:
            topology_connectivity.check_state_after_removal(master_cn)
        except ValueError as e:
            raise errors.ServerRemovalError(reason=e)

    def _remove_server_principal_references(self, master):
        """
        This method removes information about the replica in parts
        of the shared tree that expose it, so clients stop trying to
        use this replica.
        """
        conn = self.Backend.ldap2
        env = self.api.env

        master_principal = "{}@{}".format(master, env.realm).encode('utf-8')

        # remove replica memberPrincipal from s4u2proxy configuration
        s4u2proxy_subtree = DN(env.container_s4u2proxy,
                               env.basedn)
        dn1 = DN(('cn', 'ipa-http-delegation'), s4u2proxy_subtree)
        member_principal1 = b"HTTP/%s" % master_principal

        dn2 = DN(('cn', 'ipa-ldap-delegation-targets'), s4u2proxy_subtree)
        member_principal2 = b"ldap/%s" % master_principal

        dn3 = DN(('cn', 'ipa-cifs-delegation-targets'), s4u2proxy_subtree)
        member_principal3 = b"cifs/%s" % master_principal

        for (dn, member_principal) in ((dn1, member_principal1),
                                       (dn2, member_principal2),
                                       (dn3, member_principal3)):
            try:
                mod = [(ldap.MOD_DELETE, 'memberPrincipal', member_principal)]
                conn.conn.modify_s(str(dn), mod)
            except (ldap.NO_SUCH_OBJECT, ldap.NO_SUCH_ATTRIBUTE):
                logger.debug(
                    "Replica (%s) memberPrincipal (%s) not found in %s",
                    master, member_principal.decode('utf-8'), dn)
            except Exception as e:
                self.add_message(
                    messages.ServerRemovalWarning(
                        message=_("Failed to clean memberPrincipal "
                                  "%(principal)s from s4u2proxy entry %(dn)s: "
                                  "%(err)s") % dict(
                                      principal=(member_principal
                                                 .decode('utf-8')),
                                      dn=dn, err=e)))

        try:
            etc_basedn = DN(('cn', 'etc'), env.basedn)
            filter = '(dnaHostname=%s)' % master
            entries = conn.get_entries(
                etc_basedn, ldap.SCOPE_SUBTREE, filter=filter)
            if len(entries) != 0:
                for entry in entries:
                    conn.delete_entry(entry)
        except errors.NotFound:
            pass
        except Exception as e:
            self.add_message(
                messages.ServerRemovalWarning(
                    message=_(
                        "Failed to clean up DNA hostname entries for "
                        "%(master)s: %(err)s") % dict(master=master, err=e)))

        try:
            dn = DN(('cn', 'default'), ('ou', 'profile'), env.basedn)
            ret = conn.get_entry(dn)
            srvlist = ret.single_value.get('defaultServerList', '')
            srvlist = srvlist.split()
            if master in srvlist:
                srvlist.remove(master)
                attr = ' '.join(srvlist)
                ret['defaultServerList'] = attr
                conn.update_entry(ret)
        except (errors.NotFound, errors.MidairCollision,
                errors.EmptyModlist):
            pass
        except Exception as e:
            self.add_message(
                messages.ServerRemovalWarning(
                    message=_("Failed to remove server %(master)s from server "
                              "list: %(err)s") % dict(master=master, err=e)))

    def _remove_server_custodia_keys(self, ldap, master):
        """
        Delete all Custodia encryption and signing keys
        """
        conn = self.Backend.ldap2
        env = self.api.env
        # search for memberPrincipal=*/fqdn@realm
        member_filter = ldap.make_filter_from_attr(
            'memberPrincipal', "/{}@{}".format(master, env.realm),
            exact=False, leading_wildcard=True, trailing_wildcard=False)
        custodia_subtree = DN(env.container_custodia, env.basedn)
        try:
            entries = conn.get_entries(custodia_subtree,
                                       ldap.SCOPE_SUBTREE,
                                       filter=member_filter)
            for entry in entries:
                conn.delete_entry(entry)
        except errors.NotFound:
            pass
        except Exception as e:
            self.add_message(
                messages.ServerRemovalWarning(
                    message=_(
                        "Failed to clean up Custodia keys for "
                        "%(master)s: %(err)s") % dict(master=master, err=e)))

    def _remove_server_host_services(self, ldap, master):
        """
        delete server kerberos key and all its svc principals
        """
        try:
            # do not delete ldap principal if server-del command
            # has been called on a machine which is being deleted
            # since this will break replication.
            # ldap principal to be cleaned later by topology plugin
            # necessary changes to a topology plugin are tracked
            # under https://pagure.io/freeipa/issue/7359
            if master == self.api.env.host:
                filter = (
                    '(&(krbprincipalname=*/{}@{})'
                    '(!(krbprincipalname=ldap/*)))'
                    .format(master, self.api.env.realm)
                )
            else:
                filter = '(krbprincipalname=*/{}@{})'.format(
                    master, self.api.env.realm
                )

            entries = ldap.get_entries(
                self.api.env.basedn, ldap.SCOPE_SUBTREE, filter=filter
            )

            if entries:
                entries.sort(key=lambda x: len(x.dn), reverse=True)
                for entry in entries:
                    ldap.delete_entry(entry)
        except errors.NotFound:
            pass
        except Exception as e:
            self.add_message(
                messages.ServerRemovalWarning(
                    message=_("Failed to cleanup server principals/keys: "
                              "%(err)s") % dict(err=e)))

    def _cleanup_server_dns_records(self, hostname, **options):
        if not self.api.Command.dns_is_enabled(
                **options):
            return

        try:
            bindinstance.remove_master_dns_records(
                hostname, self.api.env.realm)
            dnskeysyncinstance.remove_replica_public_keys(hostname)
        except Exception as e:
            self.add_message(
                messages.ServerRemovalWarning(
                    message=_(
                        "Failed to cleanup %(hostname)s DNS entries: "
                        "%(err)s") % dict(hostname=hostname, err=e)))

            self.add_message(
                messages.ServerRemovalWarning(
                    message=_("You may need to manually remove them from the "
                              "tree")))

    def _cleanup_server_dns_config(self, hostname):
        try:
            self.api.Command.dnsserver_del(hostname)
        except errors.NotFound:
            pass

    def pre_callback(self, ldap, dn, *keys, **options):
        pkey = self.obj.get_primary_key_from_dn(dn)

        if options.get('force', False):
            self.add_message(
                messages.ServerRemovalWarning(
                    message=_("Forcing removal of %(hostname)s") % dict(
                        hostname=pkey)))

        # check the topology errors before and after removal
        self.context.topology_connectivity = topology.TopologyConnectivity(
            self.api)

        if options.get('ignore_topology_disconnect', False):
            self.add_message(
                messages.ServerRemovalWarning(
                    message=_("Ignoring topology connectivity errors.")))
        else:
            self._check_topology_connectivity(
                self.context.topology_connectivity, pkey)

        # ensure that we are not removing last CA/DNS server, DNSSec master and
        # CA renewal master
        self._ensure_last_of_role(
            pkey, ignore_last_of_role=options.get('ignore_last_of_role', False)
        )

        # remove the references to master's ldap/http principals
        self._remove_server_principal_references(pkey)

        # remove Custodia encryption and signing keys
        self._remove_server_custodia_keys(ldap, pkey)

        # finally destroy all Kerberos principals
        self._remove_server_host_services(ldap, pkey)

        # try to clean up the leftover DNS entries
        self._cleanup_server_dns_records(pkey)

        # try to clean up the DNS config from ldap
        self._cleanup_server_dns_config(pkey)

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args,
                     **call_kwargs):
        if (options.get('force', False) and isinstance(exc, errors.NotFound)
                and call_func.__name__ == 'delete_entry'):
            self.add_message(
                message=messages.ServerRemovalWarning(
                    message=_("Server has already been deleted")))
            return

        raise exc

    def _check_deleted_segments(self, hostname, topology_connectivity,
                                starting_host):

        def wait_for_segment_removal(hostname, master_cns, suffix_name,
                                     orig_errors, new_errors):
            i = 0
            while True:
                left = self.api.Command.topologysegment_find(
                    suffix_name,
                    iparepltoposegmentleftnode=hostname,
                    sizelimit=0
                )['result']
                right = self.api.Command.topologysegment_find(
                    suffix_name,
                    iparepltoposegmentrightnode=hostname,
                    sizelimit=0
                )['result']

                # Relax check if topology was or is disconnected. Disconnected
                # topology can contain segments with already deleted servers
                # Check only if segments of servers, which can contact this
                # server, and the deleted server were removed.
                # This code should handle a case where there was a topology
                # with a central node(B):  A <-> B <-> C, where A is current
                # server. After removal of B, topology will be disconnected and
                # removal of segment B <-> C won't be replicated back to server
                # A, therefore presence of the segment has to be ignored.
                if orig_errors or new_errors:
                    # use errors after deletion because we don't care if some
                    # server can't contact the deleted one
                    cant_contact_me = [e[0] for e in new_errors
                                       if starting_host in e[2]]
                    can_contact_me = set(master_cns) - set(cant_contact_me)
                    left = [
                        s for s in left if s['iparepltoposegmentrightnode'][0]
                        in can_contact_me
                    ]
                    right = [
                        s for s in right if s['iparepltoposegmentleftnode'][0]
                        in can_contact_me
                    ]

                if not left and not right:
                    self.add_message(
                        messages.ServerRemovalInfo(
                            message=_("Agreements deleted")
                        ))
                    return
                time.sleep(2)
                if i == 2:  # taking too long, something is wrong, report
                    logger.info(
                        "Waiting for removal of replication agreements")
                if i > 90:
                    logger.info("Taking too long, skipping")
                    logger.info("Following segments were not deleted:")
                    self.add_message(messages.ServerRemovalWarning(
                        message=_("Following segments were not deleted:")))
                    for s in left:
                        self.add_message(messages.ServerRemovalWarning(
                            message=u"  %s" % s['cn'][0]))
                    for s in right:
                        self.add_message(messages.ServerRemovalWarning(
                            message=u"  %s" % s['cn'][0]))
                    return
                i += 1

        topology_graphs = topology_connectivity.graphs

        orig_errors = topology_connectivity.errors
        new_errors = topology_connectivity.errors_after_master_removal(
            hostname
        )

        for suffix_name in topology_graphs:
            suffix_members = topology_graphs[suffix_name].vertices

            if hostname not in suffix_members:
                # If the server was already deleted, we can expect that all
                # removals had been done in previous run and dangling segments
                # were not deleted.
                logger.info(
                    "Skipping replication agreement deletion check for "
                    "suffix '%s'", suffix_name)
                continue

            logger.info(
                "Checking for deleted segments in suffix '%s",
                suffix_name)

            wait_for_segment_removal(
                hostname,
                list(suffix_members),
                suffix_name,
                orig_errors[suffix_name],
                new_errors[suffix_name])

    def post_callback(self, ldap, dn, *keys, **options):
        # there is no point in checking deleted segment on local host
        # we should do this only when removing other masters
        if self.api.env.host != keys[-1]:
            self._check_deleted_segments(
                keys[-1], self.context.topology_connectivity,
                self.api.env.host)

        return super(server_del, self).post_callback(
            ldap, dn, *keys, **options)


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
            raise self.obj.handle_not_found(keys[-2])

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

        ret, stdout, _stderr = server.conncheck(keys[-1])

        result = dict(
            result=(ret == 0),
            value=keys[-2],
        )

        for line in stdout.splitlines():
            messages.add_message(options['version'],
                                 result,
                                 messages.ExternalCommandOutput(line=line))

        return result


@register()
class server_state(crud.PKQuery):
    __doc__ = _("Set enabled/hidden state of a server.")

    takes_options = (
        StrEnum(
            'state',
            values=(u'enabled', u'hidden'),
            label=_('State'),
            doc=_('Server state'),
            flags={'virtual_attribute', 'no_create', 'no_search'},
        ),
    )

    msg_summary = _('Changed server state of "%(value)s".')

    has_output = output.standard_boolean

    def _check_hide_server(self, fqdn):
        result = self.api.Command.config_show()['result']
        err = []
        # single value entries
        if result.get("ca_renewal_master_server") == fqdn:
            err.append(_("Cannot hide CA renewal master."))
        if result.get("dnssec_key_master_server") == fqdn:
            err.append(_("Cannot hide DNSSec key master."))
        # multi value entries, only fail if we are the last one
        checks = [
            ("ca_server_server", "CA"),
            ("dns_server_server", "DNS"),
            ("ipa_master_server", "IPA"),
            ("kra_server_server", "KRA"),
        ]
        for key, name in checks:
            values = result.get(key, [])
            if values == [fqdn]:  # fqdn is the only entry
                err.append(
                    _("Cannot hide last enabled %(name)s server.") % {
                        'name': name
                    }
                )
        if err:
            raise errors.ValidationError(
                name=fqdn,
                error=' '.join(str(e) for e in err)
            )

    def execute(self, *keys, **options):
        fqdn = keys[0]
        if options['state'] == u'enabled':
            to_status = ENABLED
            from_status = HIDDEN
        else:
            to_status = HIDDEN
            from_status = ENABLED

        roles = self.api.Command.server_role_find(
            server_server=fqdn,
            status=from_status,
            include_master=True,
        )['result']
        from_roles = [r[u'role_servrole'] for r in roles]
        if not from_roles:
            # no server role is in source status
            raise errors.EmptyModlist

        if to_status == ENABLED:
            enable_services(fqdn)
        else:
            self._check_hide_server(fqdn)
            hide_services(fqdn)

        # update system roles
        result = self.api.Command.dns_update_system_records()
        if not result.get('value'):
            self.add_message(messages.AutomaticDNSRecordsUpdateFailed())

        return {
            'value': fqdn,
            'result': True,
        }
