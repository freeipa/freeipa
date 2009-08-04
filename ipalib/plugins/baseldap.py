# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Base classes for LDAP plugins.
"""

from ipalib import crud, errors
from ipalib import Command, Method, Object
from ipalib import Flag, List, Str
from ipalib.cli import to_cli, from_cli
from ipalib.base import NameSpace


class LDAPObject(Object):
    """
    Object representing a LDAP entry.
    """
    __public__ = frozenset((
        'backend',
        'methods',
        'properties',
        'params',
        'primary_key',
        'parent_key',
        'params_minus_pk',
        'params_minus',
        'get_dn',

        'container_dn',
        'object_name',
        'object_name_plural',
        'parent_object_name',
        'object_class',
        'object_class_config',
        'default_attributes',
        'hidden_attributes',
        'attribute_names',
        'attribute_order',
        'attribute_members',
        'get_primary_key_from_dn',
        'convert_attribute_members',
        'print_entry',
    ))
    parent_key = None

    backend_name = 'ldap2'

    container_dn = ''
    object_name = 'entry'
    object_name_plural = 'entries'
    parent_object_name = ''
    object_class = ['top']
    object_class_config = None
    default_attributes = ['']
    hidden_attributes = ['objectclass', 'aci']
    attribute_names = {}
    attribute_order = []
    attribute_members = {}

    def set_api(self, api):
        super(LDAPObject, self).set_api(api)
        parent_keys = filter(lambda p: p.parent_key, self.params())
        if len(parent_keys) > 1:
            raise ValueError(
                '%s (LDAPObject) has multiple parent keys: %s' % (
                    self.name,
                    ', '.join(p.name for p in parent_keys),
                )
            )
        if len(parent_keys) == 1:
            self.parent_key = parent_keys[0]
            self.params_minus_pk = NameSpace(
                filter(
                    lambda p: not p.primary_key and not p.parent_key,
                    self.params()
                ),
                sort=False
            )
        elif self.params_minus_pk is None:
            self.params_minus_pk = self.params

    def get_dn(self, *keys, **kwargs):
        if len(keys) > 1:
            parent_dn = self.backend.make_dn_from_attr(
                self.parent_key.name, keys[0], self.container_dn
            )
        else:
            parent_dn = self.container_dn
        return self.backend.make_dn_from_attr(
            self.primary_key.name, keys[-1], parent_dn
        )

    def get_primary_key_from_dn(self, dn):
        return dn[len(self.primary_key.name) + 1:dn.find(',')]

    def convert_attribute_members(self, entry_attrs, *keys, **options):
        if options.get('raw', False):
            return
        for attr in self.attribute_members:
            for member in entry_attrs.setdefault(attr, []):
                for ldap_obj_name in self.attribute_members[attr]:
                    ldap_obj = self.api.Object[ldap_obj_name]
                    if member.find(ldap_obj.container_dn) > 0:
                        new_attr = 'member %s' % ldap_obj.object_name_plural
                        entry_attrs.setdefault(new_attr, []).append(
                            ldap_obj.get_primary_key_from_dn(member)
                        )
            del entry_attrs[attr]

    def print_entry(self, textui, entry, *keys, **options):
        if options.get('raw', False):
            textui.print_attribute('dn', entry[0])
            textui.print_entry(entry[1], attr_order=self.attribute_order)
        else:
            if self.primary_key:
                textui.print_attribute(
                    self.object_name.capitalize(), keys[-1], indent=0
                )
            else:
                textui.print_plain(self.object_name.capitalize())
            entry_attrs = entry[1]
            for a in self.hidden_attributes:
                if a in entry_attrs:
                    del entry_attrs[a]
            textui.print_entry(
                entry_attrs, attr_map=self.attribute_names,
                attr_order=self.attribute_order
            )


class LDAPCreate(crud.Create):
    """
    Create a new entry in LDAP.
    """
    takes_options = (
        Flag('raw',
            cli_name='raw',
            doc='print entries as they are stored in LDAP',
        ),
    )

    def get_args(self):
        if self.obj.parent_key:
            yield self.obj.parent_key.clone(query=True)
        if self.obj.primary_key:
            yield self.obj.primary_key.clone(attribute=True)

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        entry_attrs = self.args_options_2_entry(*keys, **options)
        entry_attrs['objectclass'] = self.obj.object_class

        if self.obj.object_class_config:
            config = ldap.get_ipa_config()[1]
            entry_attrs['objectclass'] = config.get(
                self.obj.object_class_config, entry_attrs['objectclass']
            )

        dn = self.pre_callback(ldap, dn, entry_attrs, *keys, **options)

        ldap.add_entry(dn, entry_attrs)

        (dn, entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())

        dn = self.post_callback(ldap, dn, entry_attrs, *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        return (dn, entry_attrs)

    def output_for_cli(self, textui, entry, *keys, **options):
        textui.print_name(self.name)
        self.obj.print_entry(textui, entry, *keys, **options)
        if len(keys) > 1:
            textui.print_dashed(
                'Created %s "%s" in %s "%s".' % (
                    self.obj.object_name, keys[1], self.obj.parent_object_name,
                    keys[0]
                )
            )
        elif len(keys) == 1:
            textui.print_dashed(
                'Created %s "%s".' % (self.obj.object_name, keys[0])
            )
        else:
            textui.print_dashed('Created %s.' % self.obj.object_name)

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn


class LDAPQuery(crud.PKQuery):
    """
    Base class for commands that need to retrieve an existing entry.
    """
    def get_args(self):
        if self.obj.parent_key:
            yield self.obj.parent_key.clone(query=True)
        if self.obj.primary_key:
            yield self.obj.primary_key.clone(attribute=True, query=True)


class LDAPRetrieve(LDAPQuery):
    """
    Retrieve an LDAP entry.
    """
    takes_options = (
        Flag('raw',
            cli_name='raw',
            doc='print entries as they are stored in LDAP',
        ),
        Flag('all',
            cli_name='all',
            doc='retrieve all attributes',
        ),
    )

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        if options['all']:
            attrs_list = ['*']
        else:
            attrs_list = list(self.obj.default_attributes)

        dn = self.pre_callback(ldap, dn, attrs_list, *keys, **options)

        (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)

        dn = self.post_callback(ldap, dn, entry_attrs, *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        return (dn, entry_attrs)

    def output_for_cli(self, textui, entry, *keys, **options):
        textui.print_name(self.name)
        self.obj.print_entry(textui, entry, *keys, **options)

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, attrs_list, *keys, **options):
        return dn


class LDAPUpdate(LDAPQuery, crud.Update):
    """
    Update an LDAP entry.
    """
    takes_options = (
        Flag('raw',
            cli_name='raw',
            doc='print entries as they are stored in LDAP',
        ),
    )

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        entry_attrs = self.args_options_2_entry(**options)

        dn = self.pre_callback(ldap, dn, entry_attrs, *keys, **options)

        try:
            ldap.update_entry(dn, entry_attrs)
        except errors.EmptyModlist:
            pass

        (dn, entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())

        dn = self.post_callback(ldap, dn, entry_attrs, *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        return (dn, entry_attrs)

    def output_for_cli(self, textui, entry, *keys, **options):
        textui.print_name(self.name)
        self.obj.print_entry(textui, entry, *keys, **options)
        if len(keys) > 1:
            textui.print_dashed(
                'Modified %s "%s" in %s "%s".' % (
                    self.obj.object_name, keys[1], self.obj.parent_object_name,
                    keys[0]
                )
            )
        elif len(keys) == 1:
            textui.print_dashed(
                'Modified %s "%s".' % (self.obj.object_name, keys[0])
            )
        else:
            textui.print_dashed('Modified %s.' % self.obj.object_name)

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn


class LDAPDelete(LDAPQuery):
    """
    Delete an LDAP entry and all of its direct subentries.
    """
    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        dn = self.pre_callback(ldap, dn, *keys, **options)

        truncated = True
        while truncated:
            try:
                (subentries, truncated) = ldap.find_entries(
                    None, [''], dn, ldap.SCOPE_ONELEVEL
                )
            except errors.NotFound:
                break
            else:
                for (dn_, entry_attrs) in subentries:
                    ldap.delete_entry(dn_)

        ldap.delete_entry(dn)

        result = self.post_callback(ldap, dn, *keys, **options)

        return result

    def output_for_cli(self, textui, result, *keys, **options):
        textui.print_name(self.name)
        if len(keys) > 1:
            textui.print_dashed(
                'Deleted %s "%s" in %s "%s".' % (
                    self.obj.object_name, keys[1], self.obj.parent_object_name,
                    keys[0]
                )
            )
        elif len(keys) == 1:
            textui.print_dashed(
                'Deleted %s "%s".' % (self.obj.object_name, keys[0])
            )
        else:
            textui.print_dashed('Deleted %s.' % self.obj.object_name)

    def pre_callback(self, ldap, dn, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        return True


class LDAPModMember(LDAPQuery):
    """
    Base class for member manipulation.
    """
    member_param_doc = 'comma-separated list of %s'
    member_count_out = ('%i member processed.', '%i members processed.')

    takes_options = (
        Flag('raw',
            cli_name='raw',
            doc='print entries as they are stored in LDAP',
        ),
    )

    def get_options(self):
        for attr in self.obj.attribute_members:
            for ldap_obj_name in self.obj.attribute_members[attr]:
                ldap_obj = self.api.Object[ldap_obj_name]
                name = to_cli(ldap_obj_name)
                doc = self.member_param_doc % ldap_obj.object_name_plural
                yield List('%s?' % name, cli_name='%ss' % name, doc=doc)

    def get_member_dns(self, **options):
        dns = {}
        failed = {}
        for attr in self.obj.attribute_members:
            dns[attr] = {}
            failed[attr] = {}
            for ldap_obj_name in self.obj.attribute_members[attr]:
                dns[attr][ldap_obj_name] = []
                failed[attr][ldap_obj_name] = []
                for name in options.get(to_cli(ldap_obj_name), []):
                    if not name:
                        continue
                    ldap_obj = self.api.Object[ldap_obj_name]
                    try:
                        dns[attr][ldap_obj_name].append(ldap_obj.get_dn(name))
                    except errors.PublicError:
                        failed[attr][ldap_obj_name].append(name)
        return (dns, failed)

    def output_for_cli(self, textui, result, *keys, **options):
        (completed, failed, entry) = result

        for (attr, objs) in failed.iteritems():
            for ldap_obj_name in objs:
                if failed[attr][ldap_obj_name]:
                    failed_string = ','.join(failed[attr][ldap_obj_name])
                    textui.print_plain('%ss failed: %s' % (
                            to_cli(ldap_obj_name), failed_string
                        )
                    )
        textui.print_name(self.name)
        self.obj.print_entry(textui, entry, *keys, **options)
        textui.print_count(
            completed, self.member_count_out[0], self.member_count_out[1]
        )


class LDAPAddMember(LDAPModMember):
    """
    Add other LDAP entries to members.
    """
    member_param_doc = 'comma-separated list of %s to add'
    member_count_out = ('%i member added.', '%i members added.')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        (member_dns, failed) = self.get_member_dns(**options)

        dn = self.obj.get_dn(*keys, **options)

        dn = self.pre_callback(ldap, dn, member_dns, failed, *keys, **options)

        completed = 0
        for (attr, objs) in member_dns.iteritems():
            for ldap_obj_name in objs:
                for m_dn in member_dns[attr][ldap_obj_name]:
                    if not m_dn:
                        continue
                    try:
                        ldap.add_entry_to_group(m_dn, dn, attr)
                    except errors.PublicError:
                        ldap_obj = self.api.Object[ldap_obj_name]
                        failed[attr][ldap_obj_name].append(
                            ldap_obj.get_primary_key_from_dn(m_dn)
                        )
                    else:
                        completed += 1

        (dn, entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)

        (completed, dn) = self.post_callback(
            ldap, completed, failed, dn, entry_attrs, *keys, **options
        )

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        return (completed, failed, (dn, entry_attrs))

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        return (completed, failed)


class LDAPRemoveMember(LDAPModMember):
    """
    Remove LDAP entries from members.
    """
    member_param_doc = 'comma-separated list of %s to remove'
    member_count_out = ('%i member removed.', '%i members removed.')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        (member_dns, failed) = self.get_member_dns(**options)

        dn = self.obj.get_dn(*keys, **options)

        dn = self.pre_callback(ldap, dn, members_dns, failed, *keys, **options)

        completed = 0
        for (attr, objs) in member_dns.iteritems():
            for ldap_obj_name in objs:
                for m_dn in member_dns[attr][ldap_obj_name]:
                    if not m_dn:
                        continue
                    try:
                        ldap.remove_entry_from_group(m_dn, dn, attr)
                    except errors.PublicError:
                        ldap_obj = self.api.Object[ldap_obj_name]
                        failed[attr][ldap_obj_name].append(
                            ldap_obj.get_primary_key_from_dn(m_dn)
                        )
                    else:
                        completed += 1

        (dn, entry_attrs) = ldap.get_entry(dn, self.obj.default_attributes)

        (completed, dn) = self.post_callback(
            ldap, completed, failed, dn, entry_attrs, *keys, **options
        )

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        return (completed, add_failed, (dn, entry_attrs))

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        return (completed, dn)


class LDAPSearch(crud.Search):
    """
    Retrieve all LDAP entries matching the given criteria.
    """
    takes_options = (
        Flag('raw',
            cli_name='raw',
            doc='print entries as they are stored in LDAP',
        ),
        Flag('all',
            cli_name='all',
            doc='retrieve all attributes',
        ),
    )

    def get_args(self):
        if self.obj.parent_key:
            yield self.obj.parent_key.clone(query=True)
        yield Str('criteria?')

    def execute(self, *args, **options):
        ldap = self.obj.backend

        term = args[-1]
        if self.obj.parent_key:
            base_dn = ldap.make_dn_from_attr(
                self.obj.parent_key.name, args[0], base_dn
            )
        else:
            base_dn = self.obj.container_dn

        search_kw = self.args_options_2_entry(**options)

        if options['all']:
            attrs_list = ['*']
        else:
            attrs_list = self.obj.default_attributes + search_kw.keys()

        search_kw['objectclass'] = self.obj.object_class
        attr_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)

        search_kw = {}
        for a in self.obj.default_attributes:
            search_kw[a] = term
        term_filter = ldap.make_filter(search_kw, exact=False)

        filter = ldap.combine_filters(
            (term_filter, attr_filter), rules=ldap.MATCH_ALL
        )

        filter = self.pre_callback(
            ldap, filter, attrs_list, base_dn, *args, **options
        )

        try:
            (entries, truncated) = ldap.find_entries(
                filter, attrs_list, base_dn, scope=ldap.SCOPE_ONELEVEL
            )
        except errors.NotFound:
            (entries, truncated) = (tuple(), False)

        self.post_callback(self, ldap, entries, truncated, *args, **options)

        if options.get('raw', False):
            for i in xrange(len(entries)):
                dn = self.obj.get_primary_key_from_dn(entries[i][0])
                self.obj.convert_attribute_members(
                    entries[i][1], *keys, **options
                )
                entries[i] = (dn, entries[i][1])
        return (entries, truncated)

    def output_for_cli(self, textui, result, *args, **options):
        (entries, truncated) = result

        textui.print_name(self.name)
        for e in entries:
            self.obj.print_entry(textui, e, e[0], **options)
            textui.print_plain('')
        textui.print_count(
            len(entries),
            '%i ' + self.obj.object_name + ' matched.',
            '%i ' + self.obj.object_name_plural + ' matched.',
        )
        if truncated:
            textui.print_dashed('These results are truncated.', below=False)
            textui.print_dashed(
                'Please refine your search and try again.', above=False
            )
        elif len(entries) == 0:
            # nothing was found, return error code 1
            return 1

    def pre_callback(self, ldap, filter, attrs_list, base_dn, *args, **options):
        return filter

    def post_callback(self, ldap, entries, truncated, *args, **options):
        pass

