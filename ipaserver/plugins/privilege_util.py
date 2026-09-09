# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from ipalib import errors
from ipapython.dn import DN


def principal_has_privilege(api, principal, privilege):
    """
    Validate that the principal is a member of the specified privilege.
    If principal is None, use currently bound LDAP DN for validation.
    cn=Directory Manager is explicitly allowed
    """
    privilege_dn = api.Object.privilege.get_dn(privilege)
    ldap = api.Backend.ldap2
    if principal is None:
        dn_or_princ = DN(ldap.conn.whoami_s()[4:])
        if dn_or_princ == DN('cn=Directory Manager'):
            return True
    else:
        dn_or_princ = principal

    # First try: Check if there is a principal that has the needed
    # privilege.
    filter = ldap.make_filter({
        'krbprincipalname': dn_or_princ,
        'memberof': privilege_dn},
        rules=ldap.MATCH_ALL)
    try:
        ldap.find_entries(base_dn=api.env.basedn, filter=filter)
        return True
    except errors.NotFound:
        pass

    # Do not run ID override check for the user that has no Kerberos principal
    if principal is None:
        return False

    # Second try: Check if there is an idoverride for the principal as
    # ipaOriginalUid that has the needed privilege.
    filter = ldap.make_filter(
        {
            'objectClass': ['ipaOverrideAnchor', 'nsmemberof'],
            'ipaOriginalUid': principal,
            'memberOf': privilege_dn
        },
        rules=ldap.MATCH_ALL)
    _dn = DN(('cn', api.packages[0].idviews.DEFAULT_TRUST_VIEW_NAME),
             api.env.container_views + api.env.basedn)
    try:
        ldap.find_entries(base_dn=_dn, filter=filter)
    except errors.NotFound:
        return False
    return True
