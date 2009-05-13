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
IPA configuration.
"""

from ipalib import api, errors
from ipalib import Command
from ipalib import Int, Str

_search_options = {
    'ipaSearchTimeLimit': 'Time limit (in seconds)',
    'ipaSearchRecordsLimit': 'Record limit',
    'ipaUserSearchFields': 'User search fields',
    'ipaGroupSearchFields': 'Group search fields',
}

_user_options = {
    'ipaMaxUsernameLength': 'Maximum name length',
    'ipaHomesRootDir': 'Root for home directories',
    'ipaDefaultLoginShell': 'Default shell',
    'ipaDefaultPrimaryGroup': 'Default group',
    'ipaDefaultEmailDomain': 'Default e-mail domain',
}

_options = {
    'Search': _search_options,
    'User': _user_options,
}


class config2_mod(Command):
    """
    Modify IPA configuration options.
    """
    takes_options = (
        Int('ipamaxusernamelength?',
            cli_name='maxusername',
            doc='Max. Username length',
            minvalue=1,
            attribute=True,
        ),
        Str('ipahomesrootdir?',
            cli_name='homedirectory',
            doc='Default location of home directories',
            attribute=True,
        ),
        Str('ipadefaultloginshell?',
            cli_name='defaultshell',
            doc='Default shell for new users',
            attribute=True,
        ),
        Str('ipadefaultprimarygroup?',
            cli_name='defaultgroup',
            doc='Default group for new users',
            attribute=True,
        ),
        Str('ipadefaultemaildomain?',
            cli_name='emaildomain',
            doc='Default e-mail domain new users',
            attribute=True,
        ),
        Int('ipasearchtimelimit?',
            cli_name='searchtimelimit',
            doc='Max. amount of time (sec.) for a search (-1 is unlimited)',
            minvalue=-1,
            attribute=True,
        ),
        Int('ipasearchrecordslimit?',
            cli_name='searchrecordslimit',
            doc='Max. number of records to search (-1 is unlimited)',
            minvalue=-1,
            attribute=True,
        ),
        Str('ipausersearchfields?',
            cli_name='usersearch',
            doc='A comma-separated list of fields to search when searching for users',
            attribute=True,
        ),
        Str('ipagroupsearchfields?',
            cli_name='groupsearch',
            doc='A comma-separated list of fields to search when searching for groups',
            attribute=True,
        ),
    )

    def execute(self, *args, **options):
        """
        Execute the config-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param args: This function takes no positional arguments
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'dn' not in options
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.get_ipa_config()
        entry_attrs = self.args_options_2_entry(*args, **options)

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        return ldap.get_entry(dn, entry_attrs.keys())

    def output_for_cli(self, textui, result, *args, **options):
        (dn, entry_attrs) = result

        for p in self.params:
            textui.print_plain(p)
        textui.print_name(self.name)
        for (name, options) in _options.iteritems():
            textui.print_plain('%s options:' % name)
            for (k, v) in options.iteritems():
                k = k.lower()
                if k in entry_attrs:
                    textui.print_attribute(v, entry_attrs[k])
            textui.print_plain('')
        textui.print_dashed('Modified IPA configuration options.')

api.register(config2_mod)


class config2_show(Command):
    """
    Display IPA configuration options.
    """

    def execute(self, *args, **options):
        """
        Execute the config-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param args: Not used.
        :param kw: Not used.
        """
        assert self.api.env.use_ldap2, 'use_ldap2 is False'
        ldap = self.api.Backend.ldap2
        return ldap.get_ipa_config()

    def output_for_cli(self, textui, result, *args, **options):
        (dn, entry_attrs) = result
        count = 0

        textui.print_name(self.name)
        for (name, options) in _options.iteritems():
            textui.print_plain('%s options:' % name)
            for (k, v) in options.iteritems():
                if k in entry_attrs:
                    textui.print_attribute(v, entry_attrs[k])
                    count += 1
            textui.print_plain('')
        textui.print_count(count, '%d option', '%d options')

api.register(config2_show)

