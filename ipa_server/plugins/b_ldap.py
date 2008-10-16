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

    def make_group_dn(self, cn):
        """
        Construct user dn from cn.
        """
        return 'cn=%s,%s,%s' % (
            self.dn.escape_dn_chars(cn),
            self.api.env.container_group,
            self.api.env.basedn,
        )

    def find_entry_dn(self, key_attribute, primary_key, object_type=None):
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
            else:
                return None

        filter = "(&(%s=%s)(objectclass=%s))" % (
            key_attribute,
            self.dn.escape_dn_chars(primary_key),
            object_type
        )

        search_base = "%s, %s" % (self.api.env.container_accounts, self.api.env.basedn)

        entry = servercore.get_sub_entry(search_base, filter, ['dn', 'objectclass'])

        return entry['dn']

    def get_ipa_config(self):
        """Return a dictionary of the IPA configuration"""
        return servercore.get_ipa_config()

    def mark_entry_active(self, dn):
        return servercore.mark_entry_inactive(dn)

    def mark_entry_inactive(self, dn):
        return servercore.mark_entry_inactive(dn)

    def _generate_search_filters(self, **kw):
        """Generates a search filter based on a list of words and a list
           of fields to search against.

           Returns a tuple of two filters: (exact_match, partial_match)
        """

        # construct search pattern for a single word
        # (|(f1=word)(f2=word)...)
        exact_pattern = "(|"
        for field in kw.keys():
            exact_pattern += "(%s=%s)" % (field, kw[field])
        exact_pattern += ")"

        sub_pattern = "(|"
        for field in kw.keys():
            sub_pattern += "(%s=*%s*)" % (field, kw[field])
        sub_pattern += ")"

        # construct the giant match for all words
        exact_match_filter = "(&" + exact_pattern + ")"
        partial_match_filter = "(|" + sub_pattern + ")"

        return (exact_match_filter, partial_match_filter)

    # The CRUD operations

    def create(self, **kw):
        if servercore.entry_exists(kw['dn']):
            raise errors.DuplicateEntry("entry already exists")

        entry = ipaldap.Entry(kw['dn'])

        # dn isn't allowed to be in the entry itself
        del kw['dn']

        # Fill in our new entry
        for k in kw:
            entry.setValues(k, kw[k])

        servercore.add_entry(entry)
        return self.retrieve(entry.dn)

    def retrieve(self, dn, attributes=None):
        return servercore.get_entry_by_dn(dn, attributes)

    def update(self, dn, **kw):
        result = self.retrieve(dn, ["*"])

        entry = ipaldap.Entry((dn, servercore.convert_scalar_values(result)))

        for k in kw:
            entry.setValues(k, kw[k])

        servercore.update_entry(entry.toDict())

        return self.retrieve(dn)

    def delete(self, dn):
        return servercore.delete_entry(dn)

    def search(self, **kw):
        objectclass = kw.get('objectclass')
        if objectclass:
            del kw['objectclass']
        (exact_match_filter, partial_match_filter) = self._generate_search_filters(**kw)
        if objectclass:
            exact_match_filter = "(&(objectClass=%s)%s)" % (objectclass, exact_match_filter)
            partial_match_filter = "(&(objectClass=%s)%s)" % (objectclass, partial_match_filter)

        search_base = "%s, %s" % (self.api.env.container_accounts, self.api.env.basedn)
        try:
            exact_results = servercore.search(search_base, 
                    exact_match_filter, ["*"])
        except errors.NotFound:
            exact_results = [0]

        try:
            partial_results = servercore.search(search_base,
                    partial_match_filter, ["*"])
        except errors.NotFound:
            partial_results = [0]

        exact_counter = exact_results[0]
        partial_counter = partial_results[0]

        exact_results = exact_results[1:]
        partial_results = partial_results[1:]

        # Remove exact matches from the partial_match list
        exact_dns = set(map(lambda e: e.get('dn'), exact_results))
        partial_results = filter(lambda e: e.get('dn') not in exact_dns,
                                 partial_results)

        if (exact_counter == -1) or (partial_counter == -1):
            counter = -1
        else:
            counter = len(exact_results) + len(partial_results)

        results = [counter]
        for r in exact_results + partial_results:
            results.append(r)

        return results

api.register(ldap)
