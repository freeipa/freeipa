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
Backend plugin for LDAP.

This wraps the python-ldap bindings.
"""

import ldap as _ldap
from ipalib import api
from ipalib import errors
from ipalib.crud import CrudBackend
from ipa_server import servercore
from ipa_server import ipaldap
import ldap


class ldap(CrudBackend):
    """
    LDAP backend plugin.
    """

    dn = _ldap.dn

    def get_user_dn(self, uid):
        """
        Construct user dn from uid.
        """
        return 'uid=%s,%s,%s' % (
            self.dn.escape_dn_chars(uid),
            self.api.env.container_user,
            self.api.env.basedn,
        )

    def create(self, **kw):
        if servercore.entry_exists(kw['dn']):
            raise errors.DuplicateEntry("entry already exists")

        entry = ipaldap.Entry(kw['dn'])

        # dn isn't allowed to be in the entry itself
        del kw['dn']

        # Fill in our new entry
        for k in kw:
            entry.setValues(k, kw[k])

        return servercore.add_entry(entry)

api.register(ldap)
