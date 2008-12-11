# Authors:
#   Martin Nagy <mnagy@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
All constants centralised in one file.
"""

# The parameter system treats all these values as None:
NULLS = (None, '', u'', tuple(), [])


# Used for a tab (or indentation level) when formatting for CLI:
CLI_TAB = '  '  # Two spaces

# The section to read in the config files, i.e. [global]
CONFIG_SECTION = 'global'


# Log format for console output
LOG_FORMAT_STDERR = ': '.join([
    '%(name)s',
    '%(levelname)s',
    '%(message)s',
])


# Log format for console output when env.dubug is True:
LOG_FORMAT_STDERR_DEBUG = ' '.join([
    '%(levelname)s',
    '%(message)r',
    '%(lineno)d',
    '%(filename)s',
])


# Tab-delimited log format for file (easy to opened in a spreadsheet):
LOG_FORMAT_FILE = '\t'.join([
    '%(asctime)s',
    '%(levelname)s',
    '%(message)r', # Using %r for repr() so message is a single line
    '%(lineno)d',
    '%(pathname)s',
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
    ('container_automount', 'cn=automount'),

    # Ports, hosts, and URIs:
    ('lite_xmlrpc_port', 8888),
    ('lite_webui_port', 9999),
    ('xmlrpc_uri', 'http://localhost:8888'),
    ('ldap_uri', 'ldap://localhost:389'),
    ('ldap_host', 'localhost'),
    ('ldap_port', 389),

    # Debugging:
    ('verbose', False),
    ('debug', False),
    ('mode', 'production'),

    # Logging:
    ('log_format_stderr', LOG_FORMAT_STDERR),
    ('log_format_stderr_debug', LOG_FORMAT_STDERR_DEBUG),
    ('log_format_file', LOG_FORMAT_FILE),

    # ********************************************************
    #  The remaining keys are never set from the values here!
    # ********************************************************
    #
    # Env.__init__() or Env._bootstrap() or Env._finalize_core()
    # will have filled in all the keys below by the time DEFAULT_CONFIG
    # is merged in, so the values below are never actually used. They are
    # listed both to provide a big picture and also so DEFAULT_CONFIG contains
    # the keys that should be present after Env._finalize_core() is called.
    #
    # The values are all None so if for some reason any of these keys were
    # set from the values here, an exception will be raised.

    # Set in Env.__init__():
    ('ipalib', None), # The directory containing ipalib/__init__.py
    ('site_packages', None), # The directory contaning ipalib
    ('script', None), # sys.argv[0]
    ('bin', None), # The directory containing script
    ('home', None), # The home directory of user underwhich process is running
    ('dot_ipa', None), # ~/.ipa directory

    # Set in Env._bootstrap():
    ('in_tree', None), # Whether or not running in-tree (bool)
    ('context', None), # Name of context, default is 'default'
    ('conf', None), # Path to config file
    ('conf_default', None), # Path to common default config file
    ('conf_dir', None), # Directory containing config files

    # Set in Env._finalize_core():
    ('in_server', None), # Whether or not running in-server (bool)
    ('log', None), # Path to log file

)
