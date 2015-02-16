# Authors: Tomas Babej <tbabej@redhat.com>
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
#

from ipalib import api
from ipalib.plugable import Registry
from ipaserver.advise.base import Advice

register = Registry()


@register()
class config_fedora_authconfig(Advice):
    """
    Provides client configuration instructions using authconfig.
    """

    description = 'Authconfig instructions for configuring Fedora 18/19 '\
                  'client with IPA server without use of SSSD.'

    def get_info(self):
        self.log.debug("Hostname obtained via api.env.host")
        self.log.comment("Run the following command as a root:")
        template = "/sbin/authconfig --enableldap --ldapserver={server} "\
                   "--enablerfc2307bis --enablekrb5"
        advice = template.format(server=api.env.host)
        self.log.command(advice)
