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

"""Support for configuring multihost testing via environment variables

This is here to support tests configured for Beaker,
such as the ones at https://github.com/freeipa/tests/
"""

import os
import json
import collections

from ipapython import ipautil
from ipatests.pytest_ipa.integration.config import Config, Domain
from ipalib.constants import MAX_DOMAIN_LEVEL

TESTHOST_PREFIX = 'TESTHOST_'


_SettingInfo = collections.namedtuple('Setting', 'name var_name default')
_setting_infos = (
    # Directory on which test-specific files will be stored,
    _SettingInfo('test_dir', 'IPATEST_DIR', '/root/ipatests'),

    # File with root's private RSA key for SSH (default: ~/.ssh/id_rsa)
    _SettingInfo('ssh_key_filename', 'IPA_ROOT_SSH_KEY', None),

    # SSH password for root (used if root_ssh_key_filename is not set)
    _SettingInfo('ssh_password', 'IPA_ROOT_SSH_PASSWORD', None),

    _SettingInfo('admin_name', 'ADMINID', 'admin'),
    _SettingInfo('admin_password', 'ADMINPW', 'Secret123'),
    _SettingInfo('dirman_dn', 'ROOTDN', 'cn=Directory Manager'),
    _SettingInfo('dirman_password', 'ROOTDNPWD', None),

    # 8.8.8.8 is probably the best-known public DNS
    _SettingInfo('dns_forwarder', 'DNSFORWARD', '8.8.8.8'),
    _SettingInfo('nis_domain', 'NISDOMAIN', 'ipatest'),
    _SettingInfo('ntp_server', 'NTPSERVER', None),
    _SettingInfo('ad_admin_name', 'ADADMINID', 'Administrator'),
    _SettingInfo('ad_admin_password', 'ADADMINPW', 'Secret123'),

    _SettingInfo('ipv6', 'IPv6SETUP', False),
    _SettingInfo('debug', 'IPADEBUG', False),
    _SettingInfo('domain_level', 'DOMAINLVL', MAX_DOMAIN_LEVEL),

    _SettingInfo('log_journal_since', 'LOG_JOURNAL_SINCE', '-1h'),
)


def get_global_config(env=None):
    """Create a test config from environment variables

    If env is None, uses os.environ; otherwise env is an environment dict.

    If IPATEST_YAML_CONFIG or IPATEST_JSON_CONFIG is set,
    configuration is read from the named file.
    For YAML, the PyYAML (python-yaml) library needs to be installed.

    Otherwise, configuration is read from various curiously
    named environment variables:

    See _setting_infos for test-wide settings

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
    if env is None:
        env = os.environ
    env = dict(env)

    return config_from_env(env)


def config_from_env(env):
    if 'IPATEST_YAML_CONFIG' in env:
        try:
            import yaml
        except ImportError as e:
            raise ImportError(
                "%s, please install PyYAML package to fix it" % e)
        with open(env['IPATEST_YAML_CONFIG']) as file:
            confdict = yaml.safe_load(file)
            return Config.from_dict(confdict)

    if 'IPATEST_JSON_CONFIG' in env:
        with open(env['IPATEST_JSON_CONFIG']) as file:
            confdict = json.load(file)
            return Config.from_dict(confdict)

    env_normalize(env)

    kwargs = {s.name: env.get(s.var_name, s.default)
                for s in _setting_infos}
    kwargs['domains'] = []

    # $IPv6SETUP needs to be 'TRUE' to enable ipv6
    if isinstance(kwargs['ipv6'], str):
        kwargs['ipv6'] = (kwargs['ipv6'].upper() == 'TRUE')

    config = Config(**kwargs)

    # Either IPA master or AD can define a domain

    domain_index = 1
    while (env.get('MASTER_env%s' % domain_index) or
           env.get('AD_env%s' % domain_index) or
           env.get('AD_SUBDOMAIN_env%s' % domain_index) or
           env.get('AD_TREEDOMAIN_env%s' % domain_index)):

        if env.get('MASTER_env%s' % domain_index):
            # IPA domain takes precedence to AD domain in case of conflict
            config.domains.append(domain_from_env(env, config, domain_index,
                                                  domain_type='IPA'))
        else:
            for domain_type in ('AD', 'AD_SUBDOMAIN', 'AD_TREEDOMAIN'):
                if env.get('%s_env%s' % (domain_type, domain_index)):
                    config.domains.append(
                        domain_from_env(env, config, domain_index,
                                        domain_type=domain_type))
                    break
        domain_index += 1

    return config


def config_to_env(config, simple=True):
    """Convert this test config into environment variables"""
    try:
        env = collections.OrderedDict()
    except AttributeError:
        # Older Python versions
        env = {}

    for setting in _setting_infos:
        value = getattr(config, setting.name)
        if value in (None, False):
            env[setting.var_name] = ''
        elif value is True:
            env[setting.var_name] = 'TRUE'
        else:
            env[setting.var_name] = str(value)

    for domain in config.domains:
        env_suffix = '_env%s' % (config.domains.index(domain) + 1)
        env['DOMAIN%s' % env_suffix] = domain.name
        env['RELM%s' % env_suffix] = domain.realm
        env['BASEDN%s' % env_suffix] = str(domain.basedn)

        for role in domain.roles:
            hosts = domain.hosts_by_role(role)

            prefix = ('' if role in domain.static_roles
                        else TESTHOST_PREFIX)

            hostnames = ' '.join(h.hostname for h in hosts)
            env['%s%s%s' % (prefix, role.upper(), env_suffix)] = hostnames

            ext_hostnames = ' '.join(h.external_hostname for h in hosts)
            env['BEAKER%s%s' % (role.upper(), env_suffix)] = ext_hostnames

            ips = ' '.join(h.ip for h in hosts)
            env['BEAKER%s_IP%s' % (role.upper(), env_suffix)] = ips

            for i, host in enumerate(hosts, start=1):
                suffix = '%s%s' % (role.upper(), i)
                prefix = ('' if role in domain.static_roles
                            else TESTHOST_PREFIX)

                ext_hostname = host.external_hostname
                env['%s%s%s' % (prefix, suffix,
                                env_suffix)] = host.hostname
                env['BEAKER%s%s' % (suffix, env_suffix)] = ext_hostname
                env['BEAKER%s_IP%s' % (suffix, env_suffix)] = host.ip

    if simple:
        # Simple Vars for simplicity and backwards compatibility with older
        # tests.  This means no _env<NUM> suffix.
        if config.domains:
            default_domain = config.domains[0]
            if default_domain.master:
                env['MASTER'] = default_domain.master.hostname
                env['BEAKERMASTER'] = default_domain.master.external_hostname
                env['MASTERIP'] = default_domain.master.ip
            if default_domain.replicas:
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
            env[name] = ''

    coalesce('MASTER_env1', 'MASTER')
    coalesce('REPLICA_env1', 'REPLICA', 'SLAVE')
    coalesce('CLIENT_env1', 'CLIENT')

    coalesce('BEAKERMASTER1_env1', 'BEAKERMASTER')
    coalesce('BEAKERREPLICA1_env1', 'BEAKERREPLICA', 'BEAKERSLAVE')
    coalesce('BEAKERCLIENT1_env1', 'BEAKERCLIENT')

    def extend(name, name2):
        value = env.get(name2)
        if value and value not in env[name].split(' '):
            env[name] += ' ' + value
    extend('CLIENT_env1', 'CLIENT2')
    extend('CLIENT_env1', 'CLIENT2_env1')


def domain_from_env(env, config, index, domain_type):
    # Roles available in the domain depend on the type of the domain
    # Unix machines are added only to the IPA domains, Windows machines
    # only to the AD domains
    if domain_type == 'IPA':
        master_role = 'MASTER'
    else:
        master_role = domain_type

    env_suffix = '_env%s' % index

    master_env = '%s%s' % (master_role, env_suffix)
    hostname, _dot, domain_name = env[master_env].partition('.')
    domain = Domain(config, domain_name, domain_type)

    for role in _roles_from_env(domain, env, env_suffix):
        prefix = '' if role in domain.static_roles else TESTHOST_PREFIX
        value = env.get('%s%s%s' % (prefix, role.upper(), env_suffix), '')

        for host_index, hostname in enumerate(value.split(), start=1):
            host = host_from_env(env, domain, hostname, role,
                                 host_index, index)
            domain.hosts.append(host)

    if not domain.hosts:
        raise ValueError('No hosts defined for %s' % env_suffix)

    return domain


def _roles_from_env(domain, env, env_suffix):
    for role in domain.static_roles:
        yield role

    # Extra roles are defined via env variables of form TESTHOST_key_envX
    roles = set()
    for var in sorted(env):
        if var.startswith(TESTHOST_PREFIX) and var.endswith(env_suffix):
            variable_split = var.split('_')
            role_name = '_'.join(variable_split[1:-1])
            if (role_name and not role_name[-1].isdigit()):
                roles.add(role_name.lower())
    for role in sorted(roles):
        yield role


def domain_to_env(domain, **kwargs):
    """Return environment variables specific to this domain"""
    env = domain.config.to_env(**kwargs)

    env['DOMAIN'] = domain.name
    env['RELM'] = domain.realm
    env['BASEDN'] = str(domain.basedn)

    return env


def host_from_env(env, domain, hostname, role, index, domain_index):
    ip = env.get('BEAKER%s%s_IP_env%s' %
                 (role.upper(), index, domain_index), None)
    external_hostname = env.get(
        'BEAKER%s%s_env%s' % (role.upper(), index, domain_index), None)

    cls = domain.get_host_class({})

    return cls(domain, hostname, role, ip=ip,
               external_hostname=external_hostname)


def host_to_env(host, **kwargs):
    """Return environment variables specific to this host"""
    env = host.domain.to_env(**kwargs)

    index = host.domain.hosts.index(host) + 1
    domain_index = host.config.domains.index(host.domain) + 1

    role = host.role.upper()
    if host.role != 'master':
        role += str(index)

    env['MYHOSTNAME'] = host.hostname
    env['MYBEAKERHOSTNAME'] = host.external_hostname
    env['MYIP'] = host.ip

    prefix = ('' if host.role in host.domain.static_roles
              else TESTHOST_PREFIX)
    env_suffix = '_env%s' % domain_index
    env['MYROLE'] = '%s%s%s' % (prefix, role, env_suffix)
    env['MYENV'] = str(domain_index)

    return env


def env_to_script(env):
    return ''.join(['export %s=%s\n' % (key, ipautil.shell_quote(value))
                    for key, value in env.items()])
