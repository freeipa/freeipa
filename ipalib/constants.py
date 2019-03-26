# Authors:
#   Martin Nagy <mnagy@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

"""
All constants centralised in one file.
"""

import os
import socket
from ipapython.dn import DN
from ipapython.version import VERSION, API_VERSION

try:
    FQDN = socket.getfqdn()
except Exception:
    try:
        FQDN = socket.gethostname()
    except Exception:
        FQDN = None

# regular expression NameSpace member names must match:
NAME_REGEX = r'^[a-z][_a-z0-9]*[a-z0-9]$|^[a-z]$'

# Format for ValueError raised when name does not match above regex:
NAME_ERROR = "name must match '%s'; got '%s'"

# Standard format for TypeError message:
TYPE_ERROR = '%s: need a %r; got %r (a %r)'

# Stardard format for TypeError message when a callable is expected:
CALLABLE_ERROR = '%s: need a callable; got %r (which is a %r)'

# Standard format for Exception message when overriding an attribute:
OVERRIDE_ERROR = 'cannot override %s.%s value %r with %r'

# Standard format for AttributeError message when a read-only attribute is
# already locked:
SET_ERROR = 'locked: cannot set %s.%s to %r'
DEL_ERROR = 'locked: cannot delete %s.%s'

# Used for a tab (or indentation level) when formatting for CLI:
CLI_TAB = '  '  # Two spaces

# The section to read in the config files, i.e. [global]
CONFIG_SECTION = 'global'

# The default configuration for api.env
# This is a tuple instead of a dict so that it is immutable.
# To create a dict with this config, just "d = dict(DEFAULT_CONFIG)".
DEFAULT_CONFIG = (
    ('api_version', API_VERSION),
    ('version', VERSION),

    # Domain, realm, basedn:
    # Following values do not have any reasonable default.
    # Do not initialize them so the code which depends on them blows up early
    # and does not do crazy stuff with default values instead of real ones.
    # ('domain', 'example.com'),
    # ('realm', 'EXAMPLE.COM'),
    # ('basedn', DN(('dc', 'example'), ('dc', 'com'))),

    # LDAP containers:
    ('container_accounts', DN(('cn', 'accounts'))),
    ('container_user', DN(('cn', 'users'), ('cn', 'accounts'))),
    ('container_deleteuser', DN(('cn', 'deleted users'), ('cn', 'accounts'), ('cn', 'provisioning'))),
    ('container_stageuser',  DN(('cn', 'staged users'),  ('cn', 'accounts'), ('cn', 'provisioning'))),
    ('container_group', DN(('cn', 'groups'), ('cn', 'accounts'))),
    ('container_service', DN(('cn', 'services'), ('cn', 'accounts'))),
    ('container_host', DN(('cn', 'computers'), ('cn', 'accounts'))),
    ('container_hostgroup', DN(('cn', 'hostgroups'), ('cn', 'accounts'))),
    ('container_rolegroup', DN(('cn', 'roles'), ('cn', 'accounts'))),
    ('container_permission', DN(('cn', 'permissions'), ('cn', 'pbac'))),
    ('container_privilege', DN(('cn', 'privileges'), ('cn', 'pbac'))),
    ('container_automount', DN(('cn', 'automount'))),
    ('container_policies', DN(('cn', 'policies'))),
    ('container_configs', DN(('cn', 'configs'), ('cn', 'policies'))),
    ('container_roles', DN(('cn', 'roles'), ('cn', 'policies'))),
    ('container_applications', DN(('cn', 'applications'), ('cn', 'configs'), ('cn', 'policies'))),
    ('container_policygroups', DN(('cn', 'policygroups'), ('cn', 'configs'), ('cn', 'policies'))),
    ('container_policylinks', DN(('cn', 'policylinks'), ('cn', 'configs'), ('cn', 'policies'))),
    ('container_netgroup', DN(('cn', 'ng'), ('cn', 'alt'))),
    ('container_hbac', DN(('cn', 'hbac'))),
    ('container_hbacservice', DN(('cn', 'hbacservices'), ('cn', 'hbac'))),
    ('container_hbacservicegroup', DN(('cn', 'hbacservicegroups'), ('cn', 'hbac'))),
    ('container_dns', DN(('cn', 'dns'))),
    ('container_vault', DN(('cn', 'vaults'), ('cn', 'kra'))),
    ('container_virtual', DN(('cn', 'virtual operations'), ('cn', 'etc'))),
    ('container_sudorule', DN(('cn', 'sudorules'), ('cn', 'sudo'))),
    ('container_sudocmd', DN(('cn', 'sudocmds'), ('cn', 'sudo'))),
    ('container_sudocmdgroup', DN(('cn', 'sudocmdgroups'), ('cn', 'sudo'))),
    ('container_automember', DN(('cn', 'automember'), ('cn', 'etc'))),
    ('container_selinux', DN(('cn', 'usermap'), ('cn', 'selinux'))),
    ('container_s4u2proxy', DN(('cn', 's4u2proxy'), ('cn', 'etc'))),
    ('container_cifsdomains', DN(('cn', 'ad'), ('cn', 'etc'))),
    ('container_trusts', DN(('cn', 'trusts'))),
    ('container_adtrusts', DN(('cn', 'ad'), ('cn', 'trusts'))),
    ('container_ranges', DN(('cn', 'ranges'), ('cn', 'etc'))),
    ('container_dna', DN(('cn', 'dna'), ('cn', 'ipa'), ('cn', 'etc'))),
    ('container_dna_posix_ids', DN(('cn', 'posix-ids'), ('cn', 'dna'), ('cn', 'ipa'), ('cn', 'etc'))),
    ('container_realm_domains', DN(('cn', 'Realm Domains'), ('cn', 'ipa'), ('cn', 'etc'))),
    ('container_otp', DN(('cn', 'otp'))),
    ('container_radiusproxy', DN(('cn', 'radiusproxy'))),
    ('container_views', DN(('cn', 'views'), ('cn', 'accounts'))),
    ('container_masters', DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'))),
    ('container_certprofile', DN(('cn', 'certprofiles'), ('cn', 'ca'))),
    ('container_topology', DN(('cn', 'topology'), ('cn', 'ipa'), ('cn', 'etc'))),
    ('container_caacl', DN(('cn', 'caacls'), ('cn', 'ca'))),
    ('container_locations', DN(('cn', 'locations'), ('cn', 'etc'))),
    ('container_ca', DN(('cn', 'cas'), ('cn', 'ca'))),
    ('container_dnsservers', DN(('cn', 'servers'), ('cn', 'dns'))),
    ('container_custodia', DN(('cn', 'custodia'), ('cn', 'ipa'), ('cn', 'etc'))),
    ('container_sysaccounts', DN(('cn', 'sysaccounts'), ('cn', 'etc'))),
    ('container_certmap', DN(('cn', 'certmap'))),
    ('container_certmaprules', DN(('cn', 'certmaprules'), ('cn', 'certmap'))),
    ('container_ca_renewal', DN(('cn', 'ca_renewal'), ('cn', 'ipa'), ('cn', 'etc'))),

    # Ports, hosts, and URIs:
    # Following values do not have any reasonable default.
    # Do not initialize them so the code which depends on them blows up early
    # and does not do crazy stuff with default values instead of real ones.
    # ('server', 'localhost'),
    # ('xmlrpc_uri', 'http://localhost:8888/ipa/xml'),
    # ('jsonrpc_uri', 'http://localhost:8888/ipa/json'),
    # ('ldap_uri', 'ldap://localhost:389'),

    ('rpc_protocol', 'jsonrpc'),

    # Define an inclusive range of SSL/TLS version support
    ('tls_version_min', 'tls1.0'),
    ('tls_version_max', 'tls1.2'),

    # Time to wait for a service to start, in seconds
    ('startup_timeout', 300),
    # How long http connection should wait for reply [seconds].
    ('http_timeout', 30),
    # How long to wait for an entry to appear on a replica
    ('replication_wait_timeout', 300),

    # Web Application mount points
    ('mount_ipa', '/ipa/'),

    # WebUI stuff:
    ('webui_prod', True),

    # Session stuff:
    ('kinit_lifetime', None),

    # Debugging:
    ('verbose', 0),
    ('debug', False),
    ('startup_traceback', False),
    ('mode', 'production'),
    ('wait_for_dns', 0),

    # CA plugin:
    ('ca_host', FQDN),  # Set in Env._finalize_core()
    ('ca_port', 80),
    ('ca_agent_port', 443),
    ('ca_ee_port', 443),
    # For the following ports, None means a default specific to the installed
    # Dogtag version.
    ('ca_install_port', None),
    ('ca_agent_install_port', None),
    ('ca_ee_install_port', None),

    # Topology plugin
    ('recommended_max_agmts', 4),  # Recommended maximum number of replication
                                   # agreements

    # Special CLI:
    ('prompt_all', False),
    ('interactive', True),
    ('fallback', True),
    ('delegate', False),

    # Enable certain optional plugins:
    ('enable_ra', False),
    ('ra_plugin', 'selfsign'),
    ('dogtag_version', 9),

    # Used when verifying that the API hasn't changed. Not for production.
    ('validate_api', False),

    # Skip client vs. server API version checking. Can lead to errors/strange
    # behavior when newer clients talk to older servers. Use with caution.
    ('skip_version_check', False),

    # Ignore TTL. Perform schema call and download schema if not in cache.
    ('force_schema_check', False),

    # ********************************************************
    #  The remaining keys are never set from the values here!
    # ********************************************************
    #
    # Env._bootstrap() or Env._finalize_core() will have filled in all the keys
    # below by the time DEFAULT_CONFIG is merged in, so the values below are
    # never actually used.  They are listed both to provide a big picture and
    # also so DEFAULT_CONFIG contains at least all the keys that should be
    # present after Env._finalize_core() is called.
    #
    # Each environment variable below is sent to ``object``, which just happens
    # to be an invalid value for an environment variable, so if for some reason
    # any of these keys were set from the values here, an exception will be
    # raised.

    # Non-overridable vars set in Env._bootstrap():
    ('host', FQDN),
    ('ipalib', object),  # The directory containing ipalib/__init__.py
    ('site_packages', object),  # The directory contaning ipalib
    ('script', object),  # sys.argv[0]
    ('bin', object),  # The directory containing the script
    ('home', object),  # $HOME

    # Vars set in Env._bootstrap():
    ('in_tree', object),  # Whether or not running in-tree (bool)
    ('dot_ipa', object),  # ~/.ipa directory
    ('context', object),  # Name of context, default is 'default'
    ('confdir', object),  # Directory containing config files
    ('env_confdir', None),  # conf dir specified by IPA_CONFDIR env variable
    ('conf', object),  # File containing context specific config
    ('conf_default', object),  # File containing context independent config
    ('plugins_on_demand', object),  # Whether to finalize plugins on-demand (bool)
    ('nss_dir', object),  # Path to nssdb, default {confdir}/nssdb
    ('tls_ca_cert', object),  # Path to CA cert file

    # Set in Env._finalize_core():
    ('in_server', object),  # Whether or not running in-server (bool)
    ('logdir', object),  # Directory containing log files
    ('log', object),  # Path to context specific log file

)

LDAP_GENERALIZED_TIME_FORMAT = "%Y%m%d%H%M%SZ"

IPA_ANCHOR_PREFIX = ':IPA:'
SID_ANCHOR_PREFIX = ':SID:'

# domains levels
DOMAIN_LEVEL_0 = 0  # compat
DOMAIN_LEVEL_1 = 1  # replica promotion, topology plugin

MIN_DOMAIN_LEVEL = DOMAIN_LEVEL_0
MAX_DOMAIN_LEVEL = DOMAIN_LEVEL_1

# Constants used in generation of replication agreements and as topology
# defaults

# List of attributes that need to be excluded from replication initialization.
REPL_AGMT_TOTAL_EXCLUDES = ('entryusn',
                            'krblastsuccessfulauth',
                            'krblastfailedauth',
                            'krbloginfailedcount')

# List of attributes that need to be excluded from normal replication.
REPL_AGMT_EXCLUDES = ('memberof', 'idnssoaserial') + REPL_AGMT_TOTAL_EXCLUDES

# List of attributes that are not updated on empty replication
REPL_AGMT_STRIP_ATTRS = ('modifiersName',
                         'modifyTimestamp',
                         'internalModifiersName',
                         'internalModifyTimestamp')

DOMAIN_SUFFIX_NAME = 'domain'
CA_SUFFIX_NAME = 'ca'
PKI_GSSAPI_SERVICE_NAME = 'dogtag'
IPA_CA_CN = u'ipa'
IPA_CA_RECORD = "ipa-ca"
IPA_CA_NICKNAME = 'caSigningCert cert-pki-ca'
RENEWAL_CA_NAME = 'dogtag-ipa-ca-renew-agent'
RENEWAL_REUSE_CA_NAME = 'dogtag-ipa-ca-renew-agent-reuse'
# How long dbus clients should wait for CA certificate RPCs [seconds]
CA_DBUS_TIMEOUT = 120

# regexp definitions
PATTERN_GROUPUSER_NAME = (
    '(?!^[0-9]+$)^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*[a-zA-Z0-9_.$-]?$'
)

# Kerberos Anonymous principal name
ANON_USER = 'WELLKNOWN/ANONYMOUS'

# IPA API Framework user
IPAAPI_USER = 'ipaapi'
IPAAPI_GROUP = 'ipaapi'

# TLS related constants
TLS_VERSIONS = [
    "ssl2",
    "ssl3",
    "tls1.0",
    "tls1.1",
    "tls1.2"
]
TLS_VERSION_MINIMAL = "tls1.0"
# high ciphers without RC4, MD5, TripleDES, pre-shared key
# and secure remote password
TLS_HIGH_CIPHERS = "HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES:!PSK:!SRP"

# Use cache path
USER_CACHE_PATH = (
    os.environ.get('XDG_CACHE_HOME') or
    os.path.join(
        os.environ.get(
            'HOME',
            os.path.expanduser('~')
        ),
        '.cache'
    )
)

SOFTHSM_DNSSEC_TOKEN_LABEL = u'ipaDNSSEC'
