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


class ldap(CrudBackend):
    """
    LDAP backend plugin.
    """

    dn = _ldap.dn

    def make_user_dn(self, uid):
        """
        Construct user dn from uid.
        """
        return 'uid=%s,%s,%s' % (
            self.dn.escape_dn_chars(uid),
            self.api.env.container_user,
            self.api.env.basedn,
        )

    def find_entry_dn(self, key_attribute, primary_key, attributes=None,
                      object_type=None):
        """
        Find an existing entry's dn from an attribute
        """
        key_attribute = key_attribute.lower()
        if not object_type:
            if key_attribute == "uid": # User
                filter = "posixAccount"
            elif key_attribute == "cn": # Group
                object_type = "posixGroup"
            elif key_attribute == "krbprincipal": # Service
                object_type = "krbPrincipal"

        if not object_type:
            return None

        filter = "(&(%s=%s)(objectclass=%s))" % (
            key_attribute,
            self.dn.escape_dn_chars(primary_key),
            object_type
        )

        search_base = "%s, %s" % (self.api.env.container_accounts, self.api.env.basedn)

        entry = servercore.get_sub_entry(search_base, filter, attributes)

        return entry['dn']

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

    def retrieve(self, dn, attributes=None):
        return servercore.get_entry_by_dn(dn, attributes)

    def delete(self, dn):
        return servercore.delete_entry(dn)

api.register(ldap)
