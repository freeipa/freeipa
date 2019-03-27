# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

"""Utilities for configuration of multi-master tests"""

import logging
import random

import pytest
import pytest_multihost.config

from ipapython.dn import DN
from ipalib.constants import MAX_DOMAIN_LEVEL


class Config(pytest_multihost.config.Config):
    extra_init_args = {
        'admin_name',
        'admin_password',
        'dirman_dn',
        'dirman_password',
        'nis_domain',
        'ntp_server',
        'ad_admin_name',
        'ad_admin_password',
        'dns_forwarder',
        'domain_level',
        'log_journal_since',
    }

    def __init__(self, **kwargs):
        kwargs.setdefault('test_dir', '/root/ipatests')
        super(Config, self).__init__(**kwargs)

        admin_password = kwargs.get('admin_password') or 'Secret123'

        self.admin_name = kwargs.get('admin_name') or 'admin'
        self.admin_password = admin_password
        self.dirman_dn = DN(kwargs.get('dirman_dn') or 'cn=Directory Manager')
        self.dirman_password = kwargs.get('dirman_password') or admin_password
        self.nis_domain = kwargs.get('nis_domain') or 'ipatest'
        self.ntp_server = str(kwargs.get('ntp_server') or (
            '%s.pool.ntp.org' % random.randint(0, 3)))
        self.ad_admin_name = kwargs.get('ad_admin_name') or 'Administrator'
        self.ad_admin_password = kwargs.get('ad_admin_password') or 'Secret123'
        self.domain_level = kwargs.get('domain_level', MAX_DOMAIN_LEVEL)
        # 8.8.8.8 is probably the best-known public DNS
        self.dns_forwarder = kwargs.get('dns_forwarder') or '8.8.8.8'
        self.debug = False
        self.log_journal_since = kwargs.get('log_journal_since') or '-1h'
        if self.domain_level is None:
            self.domain_level = MAX_DOMAIN_LEVEL

    def get_domain_class(self):
        return Domain

    def get_logger(self, name):
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        return logger

    @property
    def ad_domains(self):
        return [d for d in self.domains if d.is_ad_type]

    def get_all_hosts(self):
        for domain in self.domains:
            for host in domain.hosts:
                yield host

    def to_dict(self):
        extra_args = self.extra_init_args - {'dirman_dn'}
        result = super(Config, self).to_dict(extra_args)
        result['dirman_dn'] = str(self.dirman_dn)
        return result

    @classmethod
    def from_env(cls, env):
        from ipatests.pytest_ipa.integration.env_config import config_from_env
        return config_from_env(env)

    def to_env(self, **kwargs):
        from ipatests.pytest_ipa.integration.env_config import config_to_env
        return config_to_env(self, **kwargs)

    def filter(self, descriptions):
        """Destructively filters hosts and orders domains to fit description

        By default make_multihost_fixture() skips a test case, when filter()
        returns a FilterError. Let's turn FilterError into a fatal error
        instead.
        """
        try:
            super(Config, self).filter(descriptions)
        except pytest_multihost.config.FilterError as e:
            pytest.fail(str(e))


class Domain(pytest_multihost.config.Domain):
    """Configuration for an IPA / AD domain"""
    def __init__(self, config, name, domain_type):
        self.type = str(domain_type)

        self.config = config
        self.name = str(name)
        self.hosts = []

        assert self.is_ipa_type or self.is_ad_type
        self.realm = self.name.upper()
        self.basedn = DN(*(('dc', p) for p in name.split('.')))

    @property
    def is_ipa_type(self):
        return self.type == 'IPA'

    @property
    def is_ad_type(self):
        return self.type == 'AD' or self.type.startswith('AD_')

    @property
    def static_roles(self):
        # Specific roles for each domain type are hardcoded
        if self.type == 'IPA':
            return ('master', 'replica', 'client', 'other')
        elif self.type == 'AD':
            return ('ad',)
        elif self.type == 'AD_SUBDOMAIN':
            return ('ad_subdomain',)
        elif self.type == 'AD_TREEDOMAIN':
            return ('ad_treedomain',)
        else:
            raise LookupError(self.type)

    def get_host_class(self, host_dict):
        from ipatests.pytest_ipa.integration.host import Host, WinHost

        if self.is_ipa_type:
            return Host
        elif self.is_ad_type:
            return WinHost
        else:
            raise LookupError(self.type)

    @property
    def master(self):
        return self.host_by_role('master')

    @property
    def masters(self):
        return self.hosts_by_role('master')

    @property
    def replicas(self):
        return self.hosts_by_role('replica')

    @property
    def clients(self):
        return self.hosts_by_role('client')

    @property
    def ads(self):
        return self.hosts_by_role('ad')

    @property
    def other_hosts(self):
        return self.hosts_by_role('other')

    @classmethod
    def from_env(cls, env, config, index, domain_type):
        from ipatests.pytest_ipa.integration.env_config import domain_from_env
        return domain_from_env(env, config, index, domain_type)

    def to_env(self, **kwargs):
        from ipatests.pytest_ipa.integration.env_config import domain_to_env
        return domain_to_env(self, **kwargs)
