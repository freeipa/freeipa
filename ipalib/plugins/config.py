# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
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
IPA configuration
"""

from ipalib import api
from ipalib import Bool, Int, Str
from ipalib.plugins.baseldap import *


class config(LDAPObject):
    """
    IPA configuration object
    """
    object_name = 'configuration options'
    default_attributes = [
        'ipamaxusernamelength', 'ipahomesrootdir', 'ipadefaultloginshell',
        'ipadefaultprimarygroup', 'ipadefaultdomain', 'ipasearchtimelimit',
        'ipasearchrecordslimit', 'ipausersearchfields', 'ipagroupsearchfields',
        'ipamigrationenabled', 'ipacertificatesubjectbase',
    ]
    attribute_names = {
        'ipamaxusernamelength': 'maximum username length',
        'ipahomesrootdir': 'root of home directories',
        'ipadefaultloginshell': 'default login shell',
        'ipadefaultprimarygroup': 'default primary group',
        'ipadefaultdomain': 'default e-mail domain',
        'ipasearchtimelimit': 'time limit for search queries',
        'ipasearchrecordslimit': 'result count limit for search queries',
        'ipausersearchfields': 'search fields for users',
        'ipagroupsearchfields': 'search fields for groups',
        'ipamigrationenabled': 'enable migration mode',
        'ipacertificatesubjectbase': 'base for certificate subjects',
    }

    takes_params = (
        Int('ipamaxusernamelength?',
            cli_name='maxusername',
            label='Max. Username length',
            doc='Max. Username length',
            minvalue=1,
        ),
        Str('ipahomesrootdir?',
            cli_name='homedirectory',
            label='Home Directory base',
            doc='Default location of home directories',
        ),
        Str('ipadefaultloginshell?',
            cli_name='defaultshell',
            label='Default shell',
            doc='Default shell for new users',
        ),
        Str('ipadefaultprimarygroup?',
            cli_name='defaultgroup',
            label='Default users group',
            doc='Default group for new users',
        ),
        Str('ipadefaultemaildomain?',
            cli_name='emaildomain',
            label='Default e-mail domain',
            doc='Default e-mail domain new users',
        ),
        Int('ipasearchtimelimit?',
            cli_name='searchtimelimit',
            label='Search time limit',
            doc='Max. amount of time (sec.) for a search (-1 is unlimited)',
            minvalue=-1,
        ),
        Int('ipasearchrecordslimit?',
            cli_name='searchrecordslimit',
            label='Search size limit',
            doc='Max. number of records to search (-1 is unlimited)',
            minvalue=-1,
        ),
        Str('ipausersearchfields?',
            cli_name='usersearch',
            label='User search fields',
            doc='A comma-separated list of fields to search when searching for users',
        ),
        Str('ipagroupsearchfields?',
            cli_name='groupsearch',
            label='Group search fields',
            doc='A comma-separated list of fields to search when searching for groups',
        ),
        Bool('ipamigrationenabled?',
            doc='Migration mode',
            cli_name='enable_migration',
            doc='Enabled migration mode',
        ),
        Str('ipacertificatesubjectbase?',
            label='Certificate Subject base',
            cli_name='subject',
            doc='base for certificate subjects (OU=Test,O=Example)',
        ),
    )

    def get_dn(self, *keys, **kwargs):
        return 'cn=ipaconfig,cn=etc'

api.register(config)


class config_mod(LDAPUpdate):
    """
    Modify configuration options.
    """
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if 'ipamigrationenabled' in entry_attrs:
            if entry_attrs['ipamigrationenabled']:
                entry_attrs['ipamigrationenabled'] = 'TRUE'
            else:
                entry_attrs['ipamigrationenabled'] = 'FALSE'
        return dn

api.register(config_mod)


class config_show(LDAPRetrieve):
    """
    Display configuration options.
    """

api.register(config_show)

