# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Frontend plugin for default options in IPA.
"""

from ipalib import api
from ipalib import Command # Plugin base classes
from ipalib import Str, Int  # Parameter types


class defaultoptions_mod(Command):
    """
    Options command.
    """
    takes_options = (
        Int('ipamaxusernamelength?',
            cli_name='maxusername',
            doc='Max. Username length',
            minvalue=1
        ),
        Str('ipahomesrootdir?',
            cli_name='homedirectory',
            doc='Default location of home directories'
        ),
        Str('ipadefaultloginshell?',
            cli_name='defaultshell',
            doc='Default shell for new users'
        ),
        Str('ipadefaultprimarygroup?',
            cli_name='defaultgroup',
            doc='Default group for new users'
        ),
        Str('ipadefaultemaildomain?',
            cli_name='emaildomain',
            doc='Default e-mail domain new users'
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
            doc='A comma-separated list of fields to search when searching for users'
        ),
        Str('ipagroupsearchfields?',
            cli_name='groupsearch',
            doc='A comma-separated list of fields to search when searching for groups'
        ),
    )
    def execute(self, *args, **kw):
        """
        Execute the defaultoptions-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param args: This function takes no positional arguments
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        config = ldap.get_ipa_config()
        dn = config.get('dn')

        # The LDAP routines want strings, not ints, so convert a few
        # things. Otherwise it sees a string -> int conversion as a change.
        for k in kw.iterkeys():
            if k.startswith("ipa", 0, 3) and type(kw[k]) is int:
                kw[k] = str(kw[k])

        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_plain("Default options modified")

api.register(defaultoptions_mod)

class defaultoptions_show(Command):
    'Retrieve current default options'
    def execute(self, *args, **kw):
        """
        Execute the defaultoptions-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param args: Not used.
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap
        return ldap.get_ipa_config()

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_plain("Search Configuration")
        textui.print_plain("  Search Time Limit (sec.): %s" % result.get('ipasearchtimelimit'))
        textui.print_plain("  Search Records Limit: %s" % result.get('ipasearchrecordslimit'))
        textui.print_plain("  User Search Fields: %s" % result.get('ipausersearchfields'))
        textui.print_plain("  Group Search Fields: %s" % result.get('ipagroupsearchfields'))

        textui.print_plain("")

        textui.print_plain("User Settings")
        textui.print_plain("  Max. Username Length: %s" % result.get('ipamaxusernamelength'))
        textui.print_plain("  Root for Home Directories: %s" % result.get('ipahomesrootdir'))
        textui.print_plain("  Default Shell: %s" % result.get('ipadefaultloginshell'))
        textui.print_plain("  Default User Group: %s" % result.get('ipadefaultprimarygroup'))
        textui.print_plain("Default E-mail Domain: %s" % result.get('ipadefaultemaildomain'))

api.register(defaultoptions_show)
