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
import socket
try:
    FQDN = socket.getfqdn()
except:
    try:
        FQDN = socket.gethostname()
    except:
        FQDN = None

# The parameter system treats all these values as None:
NULLS = (None, '', u'', tuple(), [])

# regular expression NameSpace member names must match:
NAME_REGEX = r'^[a-z][_a-z0-9]*[a-z0-9]$|^[a-z]$'

# Format for ValueError raised when name does not match above regex:
NAME_ERROR = 'name must match %r; got %r'

# Standard format for TypeError message:
TYPE_ERROR = '%s: need a %r; got %r (a %r)'

# Stardard format for TypeError message when a callable is expected:
CALLABLE_ERROR = '%s: need a callable; got %r (which is a %r)'

# Standard format for StandardError message when overriding an attribute:
OVERRIDE_ERROR = 'cannot override %s.%s value %r with %r'

# Standard format for AttributeError message when a read-only attribute is
# already locked:
SET_ERROR = 'locked: cannot set %s.%s to %r'
DEL_ERROR = 'locked: cannot delete %s.%s'

# Used for a tab (or indentation level) when formatting for CLI:
CLI_TAB = '  '  # Two spaces

# The section to read in the config files, i.e. [global]
CONFIG_SECTION = 'global'

# Log format for stderr:
FORMAT_STDERR = ': '.join([
    'ipa',
    '%(levelname)s',
    '%(message)s',
])

# Log format for log file:
FORMAT_FILE = '\t'.join([
    '%(created)f',
    '%(process)d',
    '%(threadName)s',
    '%(levelname)s',
    '%(message)s',
])


# The default configuration for api.env
# This is a tuple instead of a dict so that it is immutable.
# To create a dict with this config, just "d = dict(DEFAULT_CONFIG)".
DEFAULT_CONFIG = (
    # Domain, realm, basedn:
    ('domain', 'example.com'),
    ('realm', 'EXAMPLE.COM'),
    ('basedn', 'dc=example,dc=com'),

    # LDAP containers:
    ('container_accounts', 'cn=accounts'),
    ('container_user', 'cn=users,cn=accounts'),
    ('container_group', 'cn=groups,cn=accounts'),
    ('container_service', 'cn=services,cn=accounts'),
    ('container_host', 'cn=computers,cn=accounts'),
    ('container_hostgroup', 'cn=hostgroups,cn=accounts'),
    ('container_rolegroup', 'cn=roles,cn=accounts'),
    ('container_permission', 'cn=permissions,cn=pbac'),
    ('container_privilege', 'cn=privileges,cn=pbac'),
    ('container_automount', 'cn=automount'),
    ('container_policies', 'cn=policies'),
    ('container_configs', 'cn=configs,cn=policies'),
    ('container_roles', 'cn=roles,cn=policies'),
    ('container_applications', 'cn=applications,cn=configs,cn=policies'),
    ('container_policygroups', 'cn=policygroups,cn=configs,cn=policies'),
    ('container_policylinks', 'cn=policylinks,cn=configs,cn=policies'),
    ('container_netgroup', 'cn=ng,cn=alt'),
    ('container_hbac', 'cn=hbac'),
    ('container_hbacservice', 'cn=hbacservices,cn=hbac'),
    ('container_hbacservicegroup', 'cn=hbacservicegroups,cn=hbac'),
    ('container_dns', 'cn=dns'),
    ('container_virtual', 'cn=virtual operations,cn=etc'),
    ('container_sudorule', 'cn=sudorules,cn=sudo'),
    ('container_sudocmd', 'cn=sudocmds,cn=sudo'),
    ('container_sudocmdgroup', 'cn=sudocmdgroups,cn=sudo'),
    ('container_entitlements', 'cn=entitlements,cn=etc'),

    # Ports, hosts, and URIs:
    # FIXME: let's renamed xmlrpc_uri to rpc_xml_uri
    ('xmlrpc_uri', 'http://localhost:8888/ipa/xml'),
    ('rpc_json_uri', 'http://localhost:8888/ipa/json'),
    ('ldap_uri', 'ldap://localhost:389'),

    # Web Application mount points
    ('mount_ipa', '/ipa/'),
    ('mount_xmlserver', 'xml'),
    ('mount_jsonserver', 'json'),

    # WebUI stuff:
    ('webui_prod', True),
    ('webui_assets_dir', None),

    # Debugging:
    ('verbose', 0),
    ('debug', False),
    ('startup_traceback', False),
    ('mode', 'production'),

    # CA plugin:
    ('ca_host', FQDN),  # Set in Env._finalize_core()
    ('ca_port', 9180),
    ('ca_agent_port', 9443),
    ('ca_ee_port', 9444),

    # Special CLI:
    ('prompt_all', False),
    ('interactive', True),
    ('fallback', True),

    # Enable certain optional plugins:
    ('enable_ra', False),
    ('ra_plugin', 'selfsign'),

    # Used when verifying that the API hasn't changed. Not for production.
    ('validate_api', False),

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
    ('conf', object),  # File containing context specific config
    ('conf_default', object),  # File containing context independent config

    # Set in Env._finalize_core():
    ('in_server', object),  # Whether or not running in-server (bool)
    ('logdir', object),  # Directory containing log files
    ('log', object),  # Path to context specific log file

)
