# Authors:
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
Constants centralized in one file.
"""

# The section to read in the config files, i.e. [global]
CONFIG_SECTION = 'global'


# The default configuration for api.env
DEFAULT_CONFIG = (
    ('lite_xmlrpc_port', 8888),
    ('lite_webui_port', 9999),
    ('xmlrpc_uri', 'http://localhost:8888'),
    ('ldap_uri', ''),

    ('verbose', False),
    ('debug', False),

    # Env.__init__() or Env._bootstrap() or Env._finalize_core()
    # will have filled in all the keys below by the time DEFAULT_CONFIG
    # is merged in, so the values below are never actually used. They are
    # listed both to provide a big picture and so DEFAULT_CONFIG contains
    # the keys that should be present after Env._load_standard is called.

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
    ('conf', None), # Path to configuration file

    # Set in Env._finalize_core():
    ('in_server', None), # Whether or not running in-server (bool)
    ('log', None), # Path to log file

)
