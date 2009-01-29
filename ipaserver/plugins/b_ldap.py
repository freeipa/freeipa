# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
from ipaserver import servercore, ipaldap
import krbV


class ldap(CrudBackend):
    """
    LDAP backend plugin.
    """

    def __init__(self):
        self.dn = _ldap.dn
        super(ldap, self).__init__()

    def create_connection(self, ccache):
        conn = ipaldap.IPAdmin(self.env.ldap_host, self.env.ldap_port)
        principle = krbV.CCache(
            name=ccache, context=krbV.default_context()
        ).principal().name
        conn.set_krbccache(ccache, principle)
        return conn

    def destroy_connection(self):
        self.conn.unbind_s()

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
        Construct group dn from cn.
        """
        return 'cn=%s,%s,%s' % (
            self.dn.escape_dn_chars(cn),
            self.api.env.container_group,
            self.api.env.basedn,
        )

    def make_hostgroup_dn(self, cn):
        """
        Construct group of hosts dn from cn.
        """
        return 'cn=%s,%s,%s' % (
            self.dn.escape_dn_chars(cn),
            self.api.env.container_hostgroup,
            self.api.env.basedn,
        )

    def make_taskgroup_dn(self, cn):
        """
        Construct group of tasks dn from cn.
        """
        return 'cn=%s,%s,%s' % (
            self.dn.escape_dn_chars(cn),
            self.api.env.container_taskgroup,
            self.api.env.basedn,
        )

    def make_service_dn(self, principal):
        """
        Construct service principal dn from principal name
        """
        return 'krbprincipalname=%s,%s,%s' % (
            self.dn.escape_dn_chars(principal),
            self.api.env.container_service,
            self.api.env.basedn,
        )

    def make_host_dn(self, hostname):
        """
        Construct host dn from hostname
        """
        return 'cn=%s,%s,%s' % (
            self.dn.escape_dn_chars(hostname),
            self.api.env.container_host,
            self.api.env.basedn,
        )

    def get_object_type(self, attribute):
        """
        Based on attribute, make an educated guess as to the type of
        object we're looking for.
        """
        attribute = attribute.lower()
        object_type = None
        if attribute == "uid": # User
            object_type = "posixAccount"
        elif attribute == "cn": # Group
            object_type = "posixGroup"
        elif attribute == "krbprincipalname": # Service
            object_type = "krbPrincipal"

        return object_type

    def find_entry_dn(self, key_attribute, primary_key, object_type=None, base=None):
        """
        Find an existing entry's dn from an attribute
        """
        key_attribute = key_attribute.lower()
        if not object_type:
            object_type = self.get_object_type(key_attribute)
        if not object_type:
            return None

        search_filter = "(&(objectclass=%s)(%s=%s))" % (
            object_type,
            key_attribute,
            self.dn.escape_dn_chars(primary_key)
        )

        if not base:
            base = self.api.env.container_accounts

        search_base = "%s, %s" % (base, self.api.env.basedn)

        entry = servercore.get_sub_entry(search_base, search_filter, ['dn', 'objectclass'])

        return entry.get('dn')

    def get_base_entry(self, searchbase, searchfilter, attrs):
        return servercore.get_base_entry(searchbase, searchfilter, attrs)

    def get_sub_entry(self, searchbase, searchfilter, attrs):
        return servercore.get_sub_entry(searchbase, searchfilter, attrs)

    def get_one_entry(self, searchbase, searchfilter, attrs):
        return servercore.get_one_entry(searchbase, searchfilter, attrs)

    def get_ipa_config(self):
        """Return a dictionary of the IPA configuration"""
        return servercore.get_ipa_config()

    def mark_entry_active(self, dn):
        return servercore.mark_entry_active(dn)

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

    def modify_password(self, dn, **kw):
        return servercore.modify_password(dn, kw.get('oldpass'), kw.get('newpass'))

    def add_member_to_group(self, memberdn, groupdn, memberattr='member'):
        """
        Add a new member to a group.

        :param memberdn: the DN of the member to add
        :param groupdn: the DN of the group to add a member to
        """
        return servercore.add_member_to_group(memberdn, groupdn, memberattr)

    def remove_member_from_group(self, memberdn, groupdn, memberattr='member'):
        """
        Remove a new member from a group.

        :param memberdn: the DN of the member to remove
        :param groupdn: the DN of the group to remove a member from
        """
        return servercore.remove_member_from_group(memberdn, groupdn, memberattr)

    # The CRUD operations

    def strip_none(self, kw):
        """
        Remove any None values present in the LDAP attribute dict.
        """
        for (key, value) in kw.iteritems():
            if value is None:
                continue
            if type(value) in (list, tuple):
                value = filter(
                    lambda v: type(v) in (str, unicode, bool, int, float),
                    value
                )
                if len(value) > 0:
                    yield (key, value)
            else:
                assert type(value) in (str, unicode, bool, int, float)
                yield (key, value)

    def create(self, **kw):
        if servercore.entry_exists(kw['dn']):
            raise errors2.DuplicateEntry
        kw = dict(self.strip_none(kw))

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
        result = self.retrieve(dn, ["*"] + kw.keys())

        entry = ipaldap.Entry((dn, servercore.convert_scalar_values(result)))
        start_keys = kw.keys()
        kw = dict(self.strip_none(kw))
        end_keys = kw.keys()
        removed_keys = list(set(start_keys) - set(end_keys))
        for k in kw:
            entry.setValues(k, kw[k])

        for k in removed_keys:
            entry.delAttr(k)

        servercore.update_entry(entry.toDict(), removed_keys)

        return self.retrieve(dn)

    def delete(self, dn):
        return servercore.delete_entry(dn)

    def search(self, **kw):
        objectclass = kw.get('objectclass')
        sfilter = kw.get('filter')
        attributes = kw.get('attributes')
        base = kw.get('base')
        if attributes:
            del kw['attributes']
        else:
            attributes = ['*']
        if objectclass:
            del kw['objectclass']
        if base:
            del kw['base']
        if sfilter:
            del kw['filter']
        (exact_match_filter, partial_match_filter) = self._generate_search_filters(**kw)
        if objectclass:
            exact_match_filter = "(&(objectClass=%s)%s)" % (objectclass, exact_match_filter)
            partial_match_filter = "(&(objectClass=%s)%s)" % (objectclass, partial_match_filter)
        if sfilter:
            exact_match_filter = "(%s%s)" % (sfilter, exact_match_filter)
            partial_match_filter = "(%s%s)" % (sfilter, partial_match_filter)

        if not base:
            base = self.api.env.container_accounts

        search_base = "%s, %s" % (base, self.api.env.basedn)
        try:
            exact_results = servercore.search(search_base,
                    exact_match_filter, attributes)
        except errors2.NotFound:
            exact_results = [0]

        try:
            partial_results = servercore.search(search_base,
                    partial_match_filter, attributes)
        except errors2.NotFound:
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
