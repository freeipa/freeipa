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
Frontend plugins for password policy.
"""

from ipalib import frontend
from ipalib import crud
from ipalib.frontend import Param
from ipalib import api
from ipalib import errors
from ipalib import ipa_types
from ipa_server import servercore
from ipa_server import ipaldap
import ldap


class pwpolicy_mod(frontend.Command):
    'Edit existing password policy.'
    # FIXME, switch to more human-readable names at some point
    takes_options = (
        Param('krbmaxpwdlife?', type=ipa_types.Int(), doc='Max. Password Lifetime (days)'),
        Param('krbminpwdlife?', type=ipa_types.Int(), doc='Min. Password Lifetime (hours)'),
        Param('krbpwdhistorylength?', type=ipa_types.Int(), doc='Password History Size'),
        Param('krbpwdmindiffchars?', type=ipa_types.Int(), doc='Min. Number of Character Classes'),
        Param('krbpwdminlength?', type=ipa_types.Int(), doc='Min. Length of Password'),
    )
    def execute(self, *args, **kw):
        # Get the existing policy entry
        oldpolicy = servercore.get_entry_by_cn("accounts", None)

        # Convert the existing policy into an entry object
        dn = oldpolicy.get('dn')
        del oldpolicy['dn']
        entry = ipaldap.Entry((dn, servercore.convert_scalar_values(oldpolicy)))

        # FIXME: if the user passed no options should we return something
        # more than No modifications to be performed?

        policy = kw

        # The LDAP routines want strings, not ints, so convert a few
        # things. Otherwise it sees a string -> int conversion as a change.
        for k in policy.iterkeys():
            if k.startswith("krb", 0, 3):
                policy[k] = str(policy[k])

        # Convert hours and days to seconds       
        if policy.get('krbmaxpwdlife'):
            policy['krbmaxpwdlife'] = str(int(policy.get('krbmaxpwdlife')) * 86400)
        if policy.get('krbminpwdlife'):
            policy['krbminpwdlife'] = str(int(policy.get('krbminpwdlife')) * 3600)
        # Update the values passed-in
        for p in policy:
            # Values need to be strings, not integers
            entry.setValues(p, str(policy[p]))

        result = servercore.update_entry(entry.toDict())

        return result
    def forward(self, *args, **kw):
        result = super(pwpolicy_mod, self).forward(*args, **kw)
        if result:
            print "Policy modified"
api.register(pwpolicy_mod)


class pwpolicy_show(frontend.Command):
    'Retrieve current password policy'
    def execute(self, *args, **kw):
        policy = servercore.get_entry_by_cn("accounts", None)

        # convert some values for display purposes
        policy['krbmaxpwdlife'] = str(int(policy.get('krbmaxpwdlife')) / 86400)
        policy['krbminpwdlife'] = str(int(policy.get('krbminpwdlife')) / 3600)

        return policy

    def forward(self, *args, **kw):
        result = super(pwpolicy_show, self).forward(*args, **kw)
        if not result: return
        print result
api.register(pwpolicy_show)
