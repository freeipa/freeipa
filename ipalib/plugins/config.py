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
from ipalib import Int, Str
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
    }

    takes_params = (
        Int('ipamaxusernamelength?',
            cli_name='maxusername',
            doc='Max. Username length',
            minvalue=1,
        ),
        Str('ipahomesrootdir?',
            cli_name='homedirectory',
            doc='Default location of home directories',
        ),
        Str('ipadefaultloginshell?',
            cli_name='defaultshell',
            doc='Default shell for new users',
        ),
        Str('ipadefaultprimarygroup?',
            cli_name='defaultgroup',
            doc='Default group for new users',
        ),
        Str('ipadefaultemaildomain?',
            cli_name='emaildomain',
            doc='Default e-mail domain new users',
        ),
        Int('ipasearchtimelimit?',
            cli_name='searchtimelimit',
            doc='Max. amount of time (sec.) for a search (-1 is unlimited)',
            minvalue=-1,
        ),
        Int('ipasearchrecordslimit?',
            cli_name='searchrecordslimit',
            doc='Max. number of records to search (-1 is unlimited)',
            minvalue=-1,
        ),
        Str('ipausersearchfields?',
            cli_name='usersearch',
            doc='A comma-separated list of fields to search when searching for users',
        ),
        Str('ipagroupsearchfields?',
            cli_name='groupsearch',
            doc='A comma-separated list of fields to search when searching for groups',
        ),
    )

    def get_dn(self, *keys, **kwargs):
        return 'cn=ipaconfig,cn=etc'

api.register(config)


class config_mod(LDAPUpdate):
    """
    Modify configuration options.
    """

api.register(config_mod)


class config_show(LDAPRetrieve):
    """
    Display configuration options.
    """

api.register(config_show)

