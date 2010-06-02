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
Manage IPA configuration

Manage default values tha IPA uses and some tuning parameters:

 Show the current configuration:
   ipa config-show

 Modify the configuration:
   ipa config-mod --maxusername=99

The available options are:

User management options:

  --maxusername=INT     Max username length when creating/modifing a user
  --homedirectory=STR   Default location of home directories (default /home)
  --defaultshell=STR    Default shell for new users (default /bin/sh)
  --defaultgroup=STR    Default group for new users (default ipausers)
  --emaildomain=STR     Default e-mail domain new users

Search tuning options. These impact how much data is searched through and
how many records may be returned on a given search.

  --searchtimelimit=INT Max. amount of time (sec.) for a search (-1 is
                        unlimited)
  --searchrecordslimit=INT Max. number of records to search (-1 is unlimited)

Server Configuration.

  --enable-migration=BOOL Enable migration mode
  --subject=STR           base for certificate subjects (OU=Test,O=Example)

"""

from ipalib import api
from ipalib import Bool, Int, Str
from ipalib.plugins.baseldap import *
from ipalib import _


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

    takes_params = (
        Int('ipamaxusernamelength?',
            cli_name='maxusername',
            label=_('Max username length'),
            minvalue=1,
        ),
        Str('ipahomesrootdir?',
            cli_name='homedirectory',
            label=_('Home directory base'),
            doc=_('Default location of home directories'),
        ),
        Str('ipadefaultloginshell?',
            cli_name='defaultshell',
            label=_('Default shell'),
            doc=_('Default shell for new users'),
        ),
        Str('ipadefaultprimarygroup?',
            cli_name='defaultgroup',
            label=_('Default users group'),
            doc=_('Default group for new users'),
        ),
        Str('ipadefaultemaildomain?',
            cli_name='emaildomain',
            label=_('Default e-mail domain'),
            doc=_('Default e-mail domain new users'),
        ),
        Int('ipasearchtimelimit?',
            cli_name='searchtimelimit',
            label=_('Search time limit'),
            doc=_('Max. amount of time (sec.) for a search (-1 is unlimited)'),
            minvalue=-1,
        ),
        Int('ipasearchrecordslimit?',
            cli_name='searchrecordslimit',
            label=_('Search size limit'),
            doc=_('Max. number of records to search (-1 is unlimited)'),
            minvalue=-1,
        ),
        Str('ipausersearchfields?',
            cli_name='usersearch',
            label=_('User search fields'),
            doc=_('A comma-separated list of fields to search when searching for users'),
        ),
        Str('ipagroupsearchfields?',
            cli_name='groupsearch',
            label='Group search fields',
            doc=_('A comma-separated list of fields to search when searching for groups'),
        ),
        Bool('ipamigrationenabled?',
            cli_name='enable_migration',
            label=_('Migration mode'),
            doc=_('Enable migration mode'),
        ),
        Str('ipacertificatesubjectbase?',
            cli_name='subject',
            label=_('Certificate Subject base'),
            doc=_('base for certificate subjects (OU=Test,O=Example)'),
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
