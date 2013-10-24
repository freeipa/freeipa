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

import os
import collections
import random

from ipapython import ipautil
from ipapython.dn import DN
from ipapython.ipa_log_manager import log_mgr
from ipatests.test_integration.host import BaseHost, Host


class Config(object):
    def __init__(self, **kwargs):
        self.log = log_mgr.get_logger(self)

        admin_password = kwargs.get('admin_password') or 'Secret123'

        self.test_dir = kwargs.get('test_dir', '/root/ipatests')
        self.root_password = kwargs.get('root_password')
        self.root_ssh_key_filename = kwargs.get('root_ssh_key_filename')
        self.ipv6 = bool(kwargs.get('ipv6', False))
        self.debug = bool(kwargs.get('debug', False))
        self.admin_name = kwargs.get('admin_name') or 'admin'
        self.admin_password = admin_password
        self.dirman_dn = DN(kwargs.get('dirman_dn') or 'cn=Directory Manager')
        self.dirman_password = kwargs.get('dirman_password') or admin_password
        self.admin_name = kwargs.get('admin_name') or 'admin'
        # 8.8.8.8 is probably the best-known public DNS
        self.dns_forwarder = kwargs.get('dns_forwarder') or '8.8.8.8'
        self.nis_domain = kwargs.get('nis_domain') or 'ipatest'
        self.ntp_server = kwargs.get('ntp_server') or (
            '%s.pool.ntp.org' % random.randint(0, 3))
        self.ad_admin_name = kwargs.get('ad_admin_name') or 'Administrator'
        self.ad_admin_password = kwargs.get('ad_admin_password') or 'Secret123'

        if not self.root_password and not self.root_ssh_key_filename:
            self.root_ssh_key_filename = '~/.ssh/id_rsa'

        self.domains = []

    @property
    def ad_domains(self):
        return filter(lambda d: d.type == 'AD', self.domains)

    @classmethod
    def from_env(cls, env):
        """Create a test config from environment variables

        Input variables:

        DOMAIN: the domain to install in
        IPATEST_DIR: Directory on which test-specific files will be stored,
            by default /root/ipatests
        IPv6SETUP: "TRUE" if setting up with IPv6
        IPADEBUG: non-empty if debugging is turned on
        IPA_ROOT_SSH_KEY: File with root's private RSA key for SSH
            (default: ~/.ssh/id_rsa)
        IPA_ROOT_SSH_PASSWORD: SSH password for root
            (used if IPA_ROOT_SSH_KEY is not set)

        ADMINID: Administrator username
        ADMINPW: Administrator password
        ROOTDN: Directory Manager DN
        ROOTDNPWD: Directory Manager password
        ADADMINID: Active Directory Administrator username
        ADADMINPW: Active Directory Administrator password
        DNSFORWARD: DNS forwarder
        NISDOMAIN
        NTPSERVER

        MASTER_env1: FQDN of the master
        REPLICA_env1: space-separated FQDNs of the replicas
        CLIENT_env1: space-separated FQDNs of the clients
        AD_env1: space-separated FQDNs of the Active Directories
        OTHER_env1: space-separated FQDNs of other hosts
        (same for _env2, _env3, etc)
        BEAKERREPLICA1_IP_env1: IP address of replica 1 in env 1
        (same for MASTER, CLIENT, or any extra defined ROLE)

        For each machine that should be accessible to tests via extra roles,
        the following environment variable is necessary:

            TESTHOST_<role>_env1: FQDN of the machine with the extra role <role>

        You can also optionally specify the IP address of the host:
            BEAKER<role>_IP_env1: IP address of the machine of the extra role

        The framework will try to resolve the hostname to its IP address
        if not passed via this environment variable.

        Also see env_normalize() for alternate variable names
        """
        env_normalize(env)

        self = cls(test_dir=env.get('IPATEST_DIR') or '/root/ipatests',
                   ipv6=(env.get('IPv6SETUP') == 'TRUE'),
                   debug=env.get('IPADEBUG'),
                   root_password=env.get('IPA_ROOT_SSH_PASSWORD'),
                   root_ssh_key_filename=env.get('IPA_ROOT_SSH_KEY'),
                   admin_name=env.get('ADMINID'),
                   admin_password=env.get('ADMINPW'),
                   dirman_dn=env.get('ROOTDN'),
                   dirman_password=env.get('ROOTDNPWD'),
                   dns_forwarder=env.get('DNSFORWARD'),
                   nis_domain=env.get('NISDOMAIN'),
                   ntp_server=env.get('NTPSERVER'),
                   ad_admin_name=env.get('ADADMINID'),
                   ad_admin_password=env.get('ADADMINPW'),
                   )

        # Either IPA master or AD can define a domain

        domain_index = 1
        while (env.get('MASTER_env%s' % domain_index) or
               env.get('AD_env%s' % domain_index)):

            if env.get('MASTER_env%s' % domain_index):
                # IPA domain takes precedence to AD domain in case of conflict
                self.domains.append(Domain.from_env(env, self, domain_index,
                                                    domain_type='IPA'))
            else:
                self.domains.append(Domain.from_env(env, self, domain_index,
                                                    domain_type='AD'))
            domain_index += 1

        return self

    def to_env(self, simple=True):
        """Convert this test config into environment variables"""
        try:
            env = collections.OrderedDict()
        except AttributeError:
            # Older Python versions
            env = {}

        env['IPATEST_DIR'] = self.test_dir
        env['IPv6SETUP'] = 'TRUE' if self.ipv6 else ''
        env['IPADEBUG'] = 'TRUE' if self.debug else ''
        env['IPA_ROOT_SSH_PASSWORD'] = self.root_password or ''
        env['IPA_ROOT_SSH_KEY'] = self.root_ssh_key_filename or ''

        env['ADMINID'] = self.admin_name
        env['ADMINPW'] = self.admin_password

        env['ROOTDN'] = str(self.dirman_dn)
        env['ROOTDNPWD'] = self.dirman_password

        env['ADADMINID'] = self.ad_admin_name
        env['ADADMINPW'] = self.ad_admin_password

        env['DNSFORWARD'] = self.dns_forwarder
        env['NISDOMAIN'] = self.nis_domain
        env['NTPSERVER'] = self.ntp_server

        for domain in self.domains:
            env['DOMAIN%s' % domain._env] = domain.name
            env['RELM%s' % domain._env] = domain.realm
            env['BASEDN%s' % domain._env] = str(domain.basedn)

            for role in domain.roles:
                hosts = domain.hosts_by_role(role)

                hostnames = ' '.join(h.hostname for h in hosts)
                env['%s%s' % (role.upper(), domain._env)] = hostnames

                ext_hostnames = ' '.join(h.external_hostname for h in hosts)
                env['BEAKER%s%s' % (role.upper(), domain._env)] = ext_hostnames

                ips = ' '.join(h.ip for h in hosts)
                env['BEAKER%s_IP%s' % (role.upper(), domain._env)] = ips

                for i, host in enumerate(hosts, start=1):
                    suffix = '%s%s' % (role.upper(), i)
                    prefix = 'TESTHOST_' if role in domain.extra_roles else ''

                    ext_hostname = host.external_hostname
                    env['%s%s%s' % (prefix, suffix,
                                    domain._env)] = host.hostname
                    env['BEAKER%s%s' % (suffix, domain._env)] = ext_hostname
                    env['BEAKER%s_IP%s' % (suffix, domain._env)] = host.ip

        if simple:
            # Simple Vars for simplicity and backwards compatibility with older
            # tests.  This means no _env<NUM> suffix.
            if self.domains:
                default_domain = self.domains[0]
                if default_domain.master:
                    env['MASTER'] = default_domain.master.hostname
                    env['BEAKERMASTER'] = default_domain.master.external_hostname
                    env['MASTERIP'] = default_domain.master.ip
                env['SLAVE'] = env['REPLICA'] = env['REPLICA_env1']
                env['BEAKERSLAVE'] = env['BEAKERREPLICA_env1']
                env['SLAVEIP'] = env['BEAKERREPLICA_IP_env1']
                if default_domain.clients:
                    client = default_domain.clients[0]
                    env['CLIENT'] = client.hostname
                    env['BEAKERCLIENT'] = client.external_hostname
                if len(default_domain.clients) >= 2:
                    client = default_domain.clients[1]
                    env['CLIENT2'] = client.hostname
                    env['BEAKERCLIENT2'] = client.external_hostname

        return env

    def host_by_name(self, name):
        for domain in self.domains:
            try:
                return domain.host_by_name(name)
            except LookupError:
                pass
        raise LookupError(name)


def env_normalize(env):
    """Fill env variables from alternate variable names

    MASTER_env1 <- MASTER
    REPLICA_env1 <- REPLICA, SLAVE
    CLIENT_env1 <- CLIENT
    similarly for BEAKER* variants: BEAKERMASTER1_env1 <- BEAKERMASTER, etc.

    CLIENT_env1 gets extended with CLIENT2 or CLIENT2_env1
    """
    def coalesce(name, *other_names):
        """If name is not set, set it to first existing env[other_name]"""
        if name not in env:
            for other_name in other_names:
                try:
                    env[name] = env[other_name]
                except KeyError:
                    pass
                else:
                    return
            else:
                env[name] = ''
    coalesce('MASTER_env1', 'MASTER')
    coalesce('REPLICA_env1', 'REPLICA', 'SLAVE')
    coalesce('CLIENT_env1', 'CLIENT')

    coalesce('BEAKERMASTER1_env1', 'BEAKERMASTER')
    coalesce('BEAKERREPLICA1_env1', 'BEAKERREPLICA', 'BEAKERSLAVE')
    coalesce('BEAKERCLIENT1_env1', 'BEAKERCLIENT')

    def extend(name, name2):
        value = env.get(name2)
        if value:
            env[name] += ' ' + value
    extend('CLIENT_env1', 'CLIENT2')
    extend('CLIENT_env1', 'CLIENT2_env1')


class Domain(object):
    """Configuration for an IPA / AD domain"""
    def __init__(self, config, name, index, domain_type):
        self.log = log_mgr.get_logger(self)
        self.type = domain_type

        self.config = config
        self.name = name
        self.hosts = []
        self.index = index

        self._env = '_env%s' % index

        self.realm = self.name.upper()
        self.basedn = DN(*(('dc', p) for p in name.split('.')))

        self._extra_roles = tuple()  # Serves as a cache for the domain roles
        self._session_env = None

    @property
    def roles(self):
        return self.static_roles + self.extra_roles

    @property
    def static_roles(self):
        # Specific roles for each domain type are hardcoded
        if self.type == 'IPA':
            return ('master', 'client', 'replica', 'other')
        else:
            return ('ad',)

    @property
    def extra_roles(self):
        if self._extra_roles:
            return self._extra_roles

        roles = ()

        # Extra roles can be defined via env variables of form TESTHOST_key_envX
        for variable in self._session_env:
            if variable.startswith('TESTHOST'):

                variable_split = variable.split('_')

                defines_extra_role = (
                    variable.endswith(self._env) and
                    # at least 3 parts, as in TESTHOST_key_env1
                    len(variable_split) > 2 and
                    # prohibit redefining roles
                    variable_split[-2].lower() not in roles
                    )

                if defines_extra_role:
                    key = '_'.join(variable_split[1:-1])
                    roles += (key.lower(),)

        self._extra_roles = roles
        return roles

    @classmethod
    def from_env(cls, env, config, index, domain_type):

        # Roles available in the domain depend on the type of the domain
        # Unix machines are added only to the IPA domains, Windows machines
        # only to the AD domains
        if domain_type == 'IPA':
            master_role = 'MASTER'
        else:
            master_role = 'AD'

        master_env = '%s_env%s' % (master_role, index)
        hostname, dot, domain_name = env[master_env].partition('.')
        self = cls(config, domain_name, index, domain_type)
        self._session_env = env

        for role in self.roles:
            prefix = 'TESTHOST_' if role in self.extra_roles else ''
            value = env.get('%s%s%s' % (prefix, role.upper(), self._env), '')

            for index, hostname in enumerate(value.split(), start=1):
                host = BaseHost.from_env(env, self, hostname, role, index)
                self.hosts.append(host)

        if not self.hosts:
            raise ValueError('No hosts defined for %s' % self._env)

        return self

    def to_env(self, **kwargs):
        """Return environment variables specific to this domain"""
        env = self.config.to_env(**kwargs)

        env['DOMAIN'] = self.name
        env['RELM'] = self.realm
        env['BASEDN'] = str(self.basedn)

        return env

    def host_by_role(self, role):
        if self.hosts_by_role(role):
            return self.hosts_by_role(role)[0]
        else:
            raise LookupError(role)

    def hosts_by_role(self, role):
        return [h for h in self.hosts if h.role == role]

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

    def host_by_name(self, name):
        for host in self.hosts:
            if name in (host.hostname, host.external_hostname, host.shortname):
                return host
        raise LookupError(name)


def env_to_script(env):
    return ''.join(['export %s=%s\n' % (key, ipautil.shell_quote(value))
                    for key, value in env.items()])


def get_global_config():
    return Config.from_env(os.environ)
