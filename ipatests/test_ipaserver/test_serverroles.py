#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#

"""
Tests for the serverroles backend
"""

from __future__ import absolute_import

from collections import namedtuple

import ldap
import pytest

from ipaplatform.paths import paths
from ipalib import api, create_api, errors
from ipapython.dn import DN

pytestmark = pytest.mark.needs_ipaapi


def _make_service_entry(ldap_backend, dn, enabled=True, other_config=None):
    mods = {
        'objectClass': ['top', 'nsContainer', 'ipaConfigObject'],
    }
    if enabled:
        mods.update({'ipaConfigString': ['enabledService']})

    if other_config is not None:
        mods.setdefault('ipaConfigString', [])
        mods['ipaConfigString'].extend(other_config)

    return ldap_backend.make_entry(dn, **mods)


def _make_master_entry(ldap_backend, dn, ca=False):
    mods = {
        'objectClass': [
            'top',
            'nsContainer',
            'ipaReplTopoManagedServer',
            'ipaSupportedDomainLevelConfig',
            'ipaConfigObject',
        ],
        'ipaMaxDomainLevel': ['1'],
        'ipaMinDomainLevel': ['0'],
        'ipaReplTopoManagedsuffix': [str(api.env.basedn)]
    }
    if ca:
        mods['ipaReplTopoManagedsuffix'].append('o=ipaca')

    return ldap_backend.make_entry(dn, **mods)

_adtrust_agents = DN(
    ('cn', 'adtrust agents'),
    ('cn', 'sysaccounts'),
    ('cn', 'etc'),
    api.env.basedn
)


master_data = {
    'ca-dns-dnssec-keymaster-pkinit-server': {
        'services': {
            'CA': {
                'enabled': True,
            },
            'DNS': {
                'enabled': True,
            },
            'DNSKeySync': {
                'enabled': True,
            },
            'DNSSEC': {
                'enabled': True,
                'config': ['DNSSecKeyMaster']
            },
            'KDC': {
                'enabled': True,
                'config': ['pkinitEnabled']
            }
        },
        'expected_roles': {
            'enabled': ['IPA master', 'CA server', 'DNS server']
        },
        'expected_attributes': {'DNS server': 'dnssec_key_master_server',
                                'IPA master': 'pkinit_server_server'}
    },
    'ca-kra-renewal-master-pkinit-server': {
        'services': {
            'CA': {
                'enabled': True,
                'config': ['caRenewalMaster']
            },
            'KRA': {
                'enabled': True,
            },
            'KDC': {
                'enabled': True,
                'config': ['pkinitEnabled']
            },
        },
        'expected_roles': {
            'enabled': ['IPA master', 'CA server', 'KRA server']
        },
        'expected_attributes': {'CA server': 'ca_renewal_master_server',
                                'IPA master': 'pkinit_server_server'}
    },
    'dns-trust-agent': {
        'services': {
            'DNS': {
                'enabled': True,
            },
            'DNSKeySync': {
                'enabled': True,
            }
        },
        'attributes': {
            _adtrust_agents: {
                'member': ['host']
            }
        },
        'expected_roles': {
            'enabled': ['IPA master', 'DNS server', 'AD trust agent']
        }
    },
    'trust-agent': {
        'attributes': {
            _adtrust_agents: {
                'member': ['host']
            }
        },
        'expected_roles': {
            'enabled': ['IPA master', 'AD trust agent']
        }
    },
    'trust-controller-dns': {
        'services': {
            'ADTRUST': {
                'enabled': True,
            },
            'DNS': {
                'enabled': True,
            },
            'DNSKeySync': {
                'enabled': True,
            }
        },
        'attributes': {
            _adtrust_agents: {
                'member': ['host', 'cifs']
            }
        },
        'expected_roles': {
            'enabled': ['IPA master', 'AD trust agent', 'AD trust controller',
                        'DNS server']
        }
    },
    'trust-controller-ca': {
        'services': {
            'ADTRUST': {
                'enabled': True,
            },
            'CA': {
                'enabled': True,
            },
        },
        'attributes': {
            _adtrust_agents: {
                'member': ['host', 'cifs']
            }
        },
        'expected_roles': {
            'enabled': ['IPA master', 'AD trust agent', 'AD trust controller',
                        'CA server']
        }
    },
    'configured-ca': {
        'services': {
            'CA': {
                'enabled': False,
            },
        },
        'expected_roles': {
            'enabled': ['IPA master'],
            'configured': ['CA server']
        }
    },
    'configured-dns': {
        'services': {
            'DNS': {
                'enabled': False,
            },
            'DNSKeySync': {
                'enabled': False,
            }
        },
        'expected_roles': {
            'enabled': ['IPA master'],
            'configured': ['DNS server']
        }
    },
    'mixed-state-dns': {
        'services': {
            'DNS': {
                'enabled': False
            },
            'DNSKeySync': {
                'enabled': True
            }
        },
        'expected_roles': {
            'enabled': ['IPA master'],
            'configured': ['DNS server']
        }
    },
}


class MockMasterTopology:
    """
    object that will set up and tear down entries in LDAP backend to mimic
    a presence of real IPA masters with services running on them.
    """

    ipamaster_services = [u'KDC', u'HTTP', u'KPASSWD']

    def __init__(self, api_instance, domain_data):
        self.api = api_instance

        self.domain = self.api.env.domain
        self.domain_data = domain_data
        self.masters_base = DN(
            self.api.env.container_masters, self.api.env.basedn)

        self.test_master_dn = DN(
            ('cn', self.api.env.host), self.api.env.container_masters,
            self.api.env.basedn)

        self.ldap = self.api.Backend.ldap2

        self.existing_masters = {
            m['cn'][0] for m in self.api.Command.server_find(
                u'', sizelimit=0,
                pkey_only=True,
                no_members=True,
                raw=True)['result']}

        self.original_dns_configs = self._remove_test_host_attrs()

    def iter_domain_data(self):
        MasterData = namedtuple('MasterData',
                                ['dn', 'fqdn', 'services', 'attrs'])
        for name in self.domain_data:
            fqdn = self.get_fqdn(name)
            master_dn = self.get_master_dn(name)
            master_services = self.domain_data[name].get('services', {})

            master_attributes = self.domain_data[name].get('attributes', {})

            yield MasterData(
                dn=master_dn,
                fqdn=fqdn,
                services=master_services,
                attrs=master_attributes
            )

    def get_fqdn(self, name):
        return '.'.join([name, self.domain])

    def get_master_dn(self, name):
        return DN(('cn', self.get_fqdn(name)), self.masters_base)

    def get_service_dn(self, name, master_dn):
        return DN(('cn', name), master_dn)

    def _add_host_entry(self, fqdn):
        self.api.Command.host_add(fqdn, force=True)
        self.api.Command.hostgroup_add_member(u'ipaservers', host=fqdn)

    def _del_host_entry(self, fqdn):
        try:
            self.api.Command.host_del(fqdn)
        except errors.NotFound:
            pass

    def _add_service_entry(self, service, fqdn):
        return self.api.Command.service_add(
            '/'.join([service, fqdn]),
            force=True
        )

    def _del_service_entry(self, service, fqdn):
        try:
            self.api.Command.service_del(
                '/'.join([service, fqdn]),
            )
        except errors.NotFound:
            pass

    def _add_svc_entries(self, master_dn, svc_desc):
        for name in svc_desc:
            svc_dn = self.get_service_dn(name, master_dn)
            svc_mods = svc_desc[name]

            self.ldap.add_entry(
                _make_service_entry(
                    self.ldap,
                    svc_dn,
                    enabled=svc_mods['enabled'],
                    other_config=svc_mods.get('config', None)))

        self._add_ipamaster_services(master_dn)

    def _remove_svc_master_entries(self, master_dn):
        try:
            entries = self.ldap.get_entries(
                master_dn, ldap.SCOPE_SUBTREE
            )
        except errors.NotFound:
            return

        if entries:
            entries.sort(key=lambda x: len(x.dn), reverse=True)
            for entry in entries:
                self.ldap.delete_entry(entry)

    def _add_ipamaster_services(self, master_dn):
        """
        add all the service entries which are part of the IPA Master role
        """
        for svc_name in self.ipamaster_services:
            svc_dn = self.get_service_dn(svc_name, master_dn)
            try:
                self.ldap.get_entry(svc_dn)
            except errors.NotFound:
                self.ldap.add_entry(_make_service_entry(self.ldap, svc_dn))

    def _add_members(self, dn, fqdn, member_attrs):
        entry_attrs = self.ldap.get_entry(dn)

        value = entry_attrs.get('member', [])

        for a in member_attrs:

            if a == 'host':
                value.append(
                    str(self.api.Object.host.get_dn(fqdn)))
            else:
                result = self._add_service_entry(a, fqdn)['result']
                value.append(str(result['dn']))

        entry_attrs['member'] = value
        self.ldap.update_entry(entry_attrs)

    def _remove_members(self, dn, fqdn, member_attrs):
        entry_attrs = self.ldap.get_entry(dn)

        value = set(entry_attrs.get('member', []))

        if not value:
            return

        for a in member_attrs:

            if a == 'host':
                try:
                    value.remove(
                        str(self.api.Object.host.get_dn(fqdn)))
                except KeyError:
                    pass
            else:
                try:
                    value.remove(
                        str(self.api.Object.service.get_dn(
                            '/'.join([a, fqdn]))))
                except KeyError:
                    pass
                self._del_service_entry(a, fqdn)

        entry_attrs['member'] = list(value)

        try:
            self.ldap.update_entry(entry_attrs)
        except (errors.NotFound, errors.EmptyModlist):
            pass

    def _remove_test_host_attrs(self):
        original_dns_configs = []

        for attr_name in (
                'caRenewalMaster', 'dnssecKeyMaster', 'pkinitEnabled'):
            try:
                svc_entry = self.ldap.find_entry_by_attr(
                    'ipaConfigString', attr_name, 'ipaConfigObject',
                    base_dn=self.test_master_dn)
            except errors.NotFound:
                continue
            else:
                original_dns_configs.append(
                    (svc_entry.dn, list(svc_entry.get('ipaConfigString', [])))
                )
                svc_entry[u'ipaConfigString'].remove(attr_name)
                self.ldap.update_entry(svc_entry)

        return original_dns_configs

    def _restore_test_host_attrs(self):
        for dn, config in self.original_dns_configs:
            try:
                svc_entry = self.api.Backend.ldap2.get_entry(dn)
                svc_entry['ipaConfigString'] = config
                self.ldap.update_entry(svc_entry)
            except (errors.NotFound, errors.EmptyModlist):
                continue

    def setup_data(self):
        for master_data in self.iter_domain_data():
            # create host
            self._add_host_entry(master_data.fqdn)

            # create master
            self.ldap.add_entry(
                _make_master_entry(
                    self.ldap,
                    master_data.dn,
                    ca='CA' in master_data.services))

            # now add service entries
            self._add_svc_entries(master_data.dn, master_data.services)

            # optionally add some attributes required e.g. by AD trust roles
            for entry_dn, attrs in master_data.attrs.items():
                if 'member' in attrs:
                    self._add_members(
                        entry_dn,
                        master_data.fqdn,
                        attrs['member']
                    )

    def teardown_data(self):
        for master_data in self.iter_domain_data():
            # first remove the master entries and service containers
            self._remove_svc_master_entries(master_data.dn)

            # optionally clean up leftover attributes
            for entry_dn, attrs in master_data.attrs.items():
                if 'member' in attrs:
                    self._remove_members(
                        entry_dn,
                        master_data.fqdn,
                        attrs['member'],
                    )

            # finally remove host entry
            self._del_host_entry(master_data.fqdn)

        self._restore_test_host_attrs()


@pytest.fixture(scope='module')
def mock_api(request):
    test_api = create_api(mode=None)
    test_api.bootstrap(in_server=True,
                       ldap_uri=api.env.ldap_uri,
                       confdir=paths.ETC_IPA)
    test_api.finalize()

    if not test_api.Backend.ldap2.isconnected():
        test_api.Backend.ldap2.connect()

    def finalize():
        test_api.Backend.ldap2.disconnect()

    request.addfinalizer(finalize)

    return test_api


@pytest.fixture(scope='module')
def mock_masters(request, mock_api):
    """
    Populate the LDAP backend with test data
    """

    if not api.Backend.rpcclient.isconnected():
        api.Backend.rpcclient.connect()

    master_topo = MockMasterTopology(mock_api, master_data)

    def finalize():
        master_topo.teardown_data()
        if api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.disconnect()

    request.addfinalizer(finalize)

    master_topo.setup_data()

    return master_topo


def enabled_role_iter(master_data):
    for m, data in master_data.items():
        for role in data['expected_roles']['enabled']:
            yield m, role


def provided_role_iter(master_data):
    for m, data in master_data.items():
        yield m, data['expected_roles']['enabled']


def configured_role_iter(master_data):
    for m, data in master_data.items():
        if 'configured' in data['expected_roles']:
            for role in data['expected_roles']['configured']:
                yield m, role


def role_provider_iter(master_data):
    result = {}
    for m, data in master_data.items():
        for role in data['expected_roles']['enabled']:
            if role not in result:
                result[role] = []

            result[role].append(m)

    for role_name, masters in result.items():
        yield role_name, masters


def attribute_masters_iter(master_data):
    for m, data in master_data.items():
        if 'expected_attributes' in data:
            for assoc_role, attr in data['expected_attributes'].items():
                yield m, assoc_role, attr


def dns_servers_iter(master_data):
    for m, data in master_data.items():
        if "DNS server" in data['expected_roles']['enabled']:
            yield m


@pytest.fixture(params=list(enabled_role_iter(master_data)),
                ids=['role: {}, master: {}, enabled'.format(role, m)
                     for m, role in enabled_role_iter(master_data)])
def enabled_role(request):
    return request.param


@pytest.fixture(params=list(provided_role_iter(master_data)),
                ids=["{}: {}".format(m, ', '.join(roles)) for m, roles in
                     provided_role_iter(master_data)])
def provided_roles(request):
    return request.param


@pytest.fixture(params=list(configured_role_iter(master_data)),
                ids=['role: {}, master: {}, configured'.format(role, m)
                     for m, role in configured_role_iter(master_data)])
def configured_role(request):
    return request.param


@pytest.fixture(params=list(role_provider_iter(master_data)),
                ids=['{} providers'.format(role_name)
                     for role_name, _m in
                     role_provider_iter(master_data)])
def role_providers(request):
    return request.param


@pytest.fixture(params=list(attribute_masters_iter(master_data)),
                ids=['{} of {}: {}'.format(attr, role, m) for m, role, attr in
                     attribute_masters_iter(master_data)])
def attribute_providers(request):
    return request.param


@pytest.fixture(params=list(dns_servers_iter(master_data)),
                ids=list(dns_servers_iter(master_data)))
def dns_server(request):
    return request.param


class TestServerRoleStatusRetrieval:
    def retrieve_role(self, master, role, mock_api, mock_masters):
        fqdn = mock_masters.get_fqdn(master)
        return mock_api.Backend.serverroles.server_role_retrieve(
            server_server=fqdn, role_servrole=role)

    def find_role(self, role_name, mock_api, mock_masters, master=None):
        if master is not None:
            hostname = mock_masters.get_fqdn(master)
        else:
            hostname = None

        result = mock_api.Backend.serverroles.server_role_search(
            server_server=hostname,
            role_servrole=role_name)

        return [
            r for r in result if r[u'server_server'] not in
            mock_masters.existing_masters]

    def get_enabled_roles_on_master(self, master, mock_api, mock_masters):
        fqdn = mock_masters.get_fqdn(master)
        result = mock_api.Backend.serverroles.server_role_search(
            server_server=fqdn, role_servrole=None, status=u'enabled'
        )
        return sorted(set(r[u'role_servrole'] for r in result))

    def get_masters_with_enabled_role(self, role_name, mock_api, mock_masters):
        result = mock_api.Backend.serverroles.server_role_search(
            server_server=None, role_servrole=role_name)

        return sorted(
            r[u'server_server'] for r in result if
            r[u'status'] == u'enabled' and r[u'server_server'] not in
            mock_masters.existing_masters)

    def test_listing_of_enabled_role(
            self, mock_api, mock_masters, enabled_role):
        master, role_name = enabled_role
        result = self.retrieve_role(master, role_name, mock_api, mock_masters)

        assert result[0][u'status'] == u'enabled'

    def test_listing_of_configured_role(
            self, mock_api, mock_masters, configured_role):
        master, role_name = configured_role
        result = self.retrieve_role(master, role_name, mock_api, mock_masters)

        assert result[0][u'status'] == u'configured'

    def test_role_providers(
            self, mock_api, mock_masters, role_providers):
        role_name, providers = role_providers
        expected_masters = sorted(mock_masters.get_fqdn(m) for m in providers)

        actual_masters = self.get_masters_with_enabled_role(
            role_name, mock_api, mock_masters)

        assert expected_masters == actual_masters

    def test_provided_roles_on_master(
            self, mock_api, mock_masters, provided_roles):
        master, expected_roles = provided_roles
        expected_roles.sort()
        actual_roles = self.get_enabled_roles_on_master(
            master, mock_api, mock_masters)
        assert expected_roles == actual_roles

    def test_unknown_role_status_raises_notfound(self, mock_api, mock_masters):
        unknown_role = 'IAP maestr'
        fqdn = mock_masters.get_fqdn('ca-dns-dnssec-keymaster-pkinit-server')
        with pytest.raises(errors.NotFound):
            mock_api.Backend.serverroles.server_role_retrieve(
                fqdn, unknown_role)

    def test_no_servrole_queries_all_roles_on_server(self, mock_api,
                                                     mock_masters):
        master_name = 'ca-dns-dnssec-keymaster-pkinit-server'
        enabled_roles = master_data[master_name]['expected_roles']['enabled']
        result = self.find_role(None, mock_api, mock_masters,
                                master=master_name)

        for r in result:
            if r[u'role_servrole'] in enabled_roles:
                assert r[u'status'] == u'enabled'
            else:
                assert r[u'status'] == u'absent'

    def test_invalid_substring_search_returns_nothing(self, mock_api,
                                                      mock_masters):
        invalid_substr = 'fwfgbb'

        assert (not self.find_role(invalid_substr, mock_api, mock_masters,
                                   'ca-dns-dnssec-keymaster-pkinit-server'))


class TestServerAttributes:
    def config_retrieve(self, assoc_role_name, mock_api):
        return mock_api.Backend.serverroles.config_retrieve(
            assoc_role_name)

    def config_update(self, mock_api, **attrs_values):
        return mock_api.Backend.serverroles.config_update(**attrs_values)

    def test_attribute_master(self, mock_api, mock_masters,
                              attribute_providers):
        master, assoc_role, attr_name = attribute_providers
        fqdn = mock_masters.get_fqdn(master)
        actual_attr_masters = self.config_retrieve(
            assoc_role, mock_api)[attr_name]

        assert fqdn in actual_attr_masters

    def test_set_attribute_on_the_same_provider_raises_emptymodlist(
            self, mock_api, mock_masters):
        attr_name = "ca_renewal_master_server"
        role_name = "CA server"

        existing_renewal_master = self.config_retrieve(
            role_name, mock_api)[attr_name]

        with pytest.raises(errors.EmptyModlist):
            self.config_update(
                mock_api, **{attr_name: existing_renewal_master})

    def test_set_attribute_on_master_without_assoc_role_raises_validationerror(
            self, mock_api, mock_masters):
        attr_name = "ca_renewal_master_server"

        non_ca_fqdn = mock_masters.get_fqdn('trust-controller-dns')

        with pytest.raises(errors.ValidationError):
            self.config_update(mock_api, **{attr_name: non_ca_fqdn})

    def test_set_unknown_attribute_on_master_raises_notfound(
            self, mock_api, mock_masters):
        attr_name = "ca_renuwal_maztah"
        fqdn = mock_masters.get_fqdn('trust-controller-ca')

        with pytest.raises(errors.NotFound):
            self.config_update(mock_api, **{attr_name: [fqdn]})

    def test_set_ca_renewal_master_on_other_ca_and_back(self, mock_api,
                                                        mock_masters):
        attr_name = "ca_renewal_master_server"
        role_name = "CA server"
        original_renewal_master = self.config_retrieve(
            role_name, mock_api)[attr_name]

        other_ca_server = mock_masters.get_fqdn('trust-controller-ca')

        for host in (other_ca_server, original_renewal_master):
            self.config_update(mock_api, **{attr_name: host})

            assert (
                self.config_retrieve(role_name, mock_api)[attr_name] == host)
