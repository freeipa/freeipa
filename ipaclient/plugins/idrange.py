# Authors:
#     Sumit Bose <sbose@redhat.com>
#
# Copyright (C) 2012  Red Hat
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

from ipaclient.frontend import MethodOverride
from ipalib.plugable import Registry
from ipalib import api

register = Registry()


@register(override=True, no_fail=True)
class idrange_add(MethodOverride):
    def interactive_prompt_callback(self, kw):
        """
        Ensure that rid-base is prompted for when dom-sid is specified.

        Also ensure that secondary-rid-base is prompted for when rid-base is
        specified and vice versa, in case that dom-sid was not specified.

        Also ensure that rid-base and secondary-rid-base is prompted for
        if ipa-adtrust-install has been run on the system.
        """

        # dom-sid can be specified using dom-sid or dom-name options

        # it can be also set using --setattr or --addattr, in these cases
        # we will not prompt, but raise an ValidationError later

        dom_sid_set = any(dom_id in kw for dom_id in
                          ('ipanttrusteddomainname', 'ipanttrusteddomainsid'))

        rid_base = kw.get('ipabaserid', None)
        secondary_rid_base = kw.get('ipasecondarybaserid', None)
        range_type = kw.get('iparangetype', None)

        def set_from_prompt(param):
            value = self.prompt_param(self.params[param])
            update = {param: value}
            kw.update(update)

        if dom_sid_set:
            # This is a trusted range

            # Prompt for RID base if domain SID / name was given
            if rid_base is None and range_type != u'ipa-ad-trust-posix':
                set_from_prompt('ipabaserid')

        else:
            # This is a local range
            # Find out whether ipa-adtrust-install has been ran
            adtrust_is_enabled = api.Command['adtrust_is_enabled']()['result']

            if adtrust_is_enabled:
                # If ipa-adtrust-install has been ran, all local ranges
                # require both RID base and secondary RID base

                if rid_base is None:
                    set_from_prompt('ipabaserid')

                if secondary_rid_base is None:
                    set_from_prompt('ipasecondarybaserid')

            else:
                # This is a local range on a server with no adtrust support

                # Prompt for secondary RID base only if RID base was given
                if rid_base is not None and secondary_rid_base is None:
                    set_from_prompt('ipasecondarybaserid')

                # Symetrically, prompt for RID base if secondary RID base was
                # given
                if rid_base is None and secondary_rid_base is not None:
                    set_from_prompt('ipabaserid')
