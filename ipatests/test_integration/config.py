# Authors:
#   Petr Viktorin <pviktori@redhat.com>
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
import socket

from ipapython import ipautil
from ipapython.dn import DN
from ipapython.ipa_log_manager import log_mgr


class Config(object):
    def __init__(self, **kwargs):
        self.log = log_mgr.get_logger(self)

        admin_password = kwargs.get('admin_password') or 'Secret123'

        self.test_dir = kwargs.get('test_dir', '/root/ipatests')
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

        self.domains = []

    @classmethod
    def from_env(cls, env):
        """Create a test config from environment variables

        Input variables:

        DOMAIN: the domain to install in
        IPATEST_DIR: Directory on which test-specific files will be stored,
            by default /root/ipatests
        IPv6SETUP: "TRUE" if setting up with IPv6
        IPADEBUG: non-empty if debugging is turned on

        ADMINID: Administrator username
        ADMINPW: Administrator password
        ROOTDN: Directory Manager DN
        ROOTDNPWD: Directory Manager password
        DNSFORWARD: DNS forwarder
        NISDOMAIN
        NTPSERVER

        MASTER_env1: FQDN of the master
        REPLICA_env1: space-separated FQDNs of the replicas
        CLIENT_env1: space-separated FQDNs of the clients
        OTHER_env1: space-separated FQDNs of other hosts
        (same for _env2, _env3, etc)

        Also see env_normalize() for alternate variable names
        """
        env_normalize(env)

        self = cls(test_dir=env.get('IPATEST_DIR') or '/root/ipatests',
                   ipv6=(env.get('IPv6SETUP') == 'TRUE'),
                   debug=env.get('IPADEBUG'),
                   admin_name=env.get('ADMINID'),
                   admin_password=env.get('ADMINPW'),
                   dirman_dn=env.get('ROOTDN'),
                   dirman_password=env.get('ROOTDNPWD'),
                   dns_forwarder=env.get('DNSFORWARD'),
                   nis_domain=env.get('NISDOMAIN'),
                   ntp_server=env.get('NTPSERVER'),
                   )

        domain_index = 1
        while env.get('MASTER_env%s' % domain_index):
            self.domains.append(Domain.from_env(env, self, domain_index))
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

        env['ADMINID'] = self.admin_name
        env['ADMINPW'] = self.admin_password

        env['ROOTDN'] = str(self.dirman_dn)
        env['ROOTDNPWD'] = self.dirman_password

        env['DNSFORWARD'] = self.dns_forwarder
        env['NISDOMAIN'] = self.nis_domain
        env['NTPSERVER'] = self.ntp_server

        for domain in self.domains:
            env['DOMAIN%s' % domain._env] = domain.name
            env['RELM%s' % domain._env] = domain.realm
            env['BASEDN%s' % domain._env] = str(domain.basedn)

            for role, hosts in [('MASTER', domain.masters),
                                ('REPLICA', domain.replicas),
                                ('CLIENT', domain.clients),
                                ('OTHER', domain.other_hosts)]:
                hostnames = ' '.join(h.hostname for h in hosts)
                env['%s%s' % (role, domain._env)] = hostnames

                ext_hostnames = ' '.join(h.external_hostname for h in hosts)
                env['BEAKER%s%s' % (role, domain._env)] = ext_hostnames

                ips = ' '.join(h.ip for h in hosts)
                env['BEAKER%s_IP%s' % (role, domain._env)] = ips

                for i, host in enumerate(hosts, start=1):
                    suffix = '%s%s' % (role, i)
                    ext_hostname = host.external_hostname
                    env['%s%s' % (suffix, domain._env)] = host.hostname
                    env['BEAKER%s%s' % (suffix, domain._env)] = ext_hostname
                    env['BEAKER%s_IP%s' % (suffix, domain._env)] = host.ip

        if simple:
            # Simple Vars for simplicity and backwards compatibility with older
            # tests.  This means no _env<NUM> suffix.
            if self.domains:
                default_domain = self.domains[0]
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
    REPLICA_env1 <- REPLICA
    CLIENT_env1 <- CLIENT, SLAVE
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
    coalesce('REPLICA_env1', 'REPLICA')
    coalesce('CLIENT_env1', 'CLIENT', 'SLAVE')

    def extend(name, name2):
        value = env.get(name2)
        if value:
            env[name] += ' ' + value
    extend('CLIENT_env1', 'CLIENT2')
    extend('CLIENT_env1', 'CLIENT2_env1')


class Domain(object):
    """Configuration for an IPA domain"""
    def __init__(self, config, name, index):
        self.log = log_mgr.get_logger(self)

        self.config = config
        self.name = name
        self.hosts = []
        self.index = index

        self._env = '_env%s' % index

        self.realm = self.name.upper()
        self.basedn = DN(*(('dc', p) for p in name.split('.')))

    @classmethod
    def from_env(cls, env, config, index):
        try:
            default_domain = env['DOMAIN']
        except KeyError:
            hostname, dot, default_domain = env['MASTER_env1'].partition('.')
        parts = default_domain.split('.')

        if index == 1:
            name = default_domain
        else:
            # For $DOMAIN = dom.example.com, additional domains are
            # dom1.example.com, dom2.example.com, etc.
            parts[0] += str(index)
            name = '.'.join(parts)

        self = cls(config, name, index)

        for role in 'master', 'replica', 'client', 'other':
            value = env.get('%s%s' % (role.upper(), self._env), '')
            for hostname in value.split():
                host = Host.from_env(env, self, hostname, role, 1)
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

    @property
    def master(self):
        return self.masters[0]

    @property
    def masters(self):
        return [h for h in self.hosts if h.role == 'master']

    @property
    def replicas(self):
        return [h for h in self.hosts if h.role == 'replica']

    @property
    def clients(self):
        return [h for h in self.hosts if h.role == 'client']

    @property
    def other_hosts(self):
        return [h for h in self.hosts
                if h.role not in ('master', 'client', 'replica')]

    def host_by_name(self, name):
        for host in self.hosts:
            if host.hostname == name or host.external_hostname == name:
                return host
        raise LookupError(name)


class Host(object):
    """Configuration for an IPA host"""
    def __init__(self, domain, hostname, role, index):
        self.log = log_mgr.get_logger(self)
        self.domain = domain
        self.role = role
        self.index = index

        shortname, dot, ext_domain = hostname.partition('.')
        self.hostname = shortname + '.' + self.domain.name
        self.external_hostname = hostname

        if self.config.ipv6:
            # $(dig +short $M $rrtype|tail -1)
            stdout, stderr, returncode = ipautil.run(
                ['dig', '+short', self.external_hostname, 'AAAA'])
            self.ip = stdout.splitlines()[-1].strip()
        else:
            try:
                self.ip = socket.gethostbyname(self.external_hostname)
            except socket.gaierror:
                self.ip = None

        if not self.ip:
            self.ip = ''
            self.role = 'other'

    @classmethod
    def from_env(cls, env, domain, hostname, role, index):
        self = cls(domain, hostname, role, index)
        return self

    @property
    def config(self):
        return self.domain.config

    def to_env(self, **kwargs):
        """Return environment variables specific to this host"""
        env = self.domain.to_env(**kwargs)

        role = self.role.upper()
        if self.role != 'master':
            role += str(self.index)

        env['MYHOSTNAME'] = self.hostname
        env['MYBREAKERHOSTNAME'] = self.external_hostname
        env['MYIP'] = self.ip

        env['MYROLE'] = '%s%s' % (role, self.domain._env)
        env['MYENV'] = str(self.domain.index)

        return env


def env_to_script(env):
    return ''.join(['export %s=%s\n' % (key, ipautil.shell_quote(value))
                    for key, value in env.items()])


def get_global_config():
    return Config.from_env(os.environ)
