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
from ipalib import Object
from ipalib import Flag, Str
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

    def get_dn(self, *keys, **kwargs):
        if len(keys) > 1:
            parent_dn = self.backend.make_dn_from_attr(
                self.parent_key.name, keys[0], self.container_dn
            )
            return self.backend.make_dn_from_attr(
                self.primary_key.name, keys[1], parent_dn
            )
        return self.backend.make_dn_from_attr(
            self.primary_key.name, keys[0], self.container_dn
        )


class LDAPCreate(crud.Create):
    """
    Create a new entry in LDAP.
    """
    def get_args(self):
        if self.obj.parent_key:
            yield self.obj.parent_key.clone(query=True)
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

        return (dn, entry_attrs)

    def output_for_cli(self, textui, entry, *keys, **options):
        (dn, entry_attrs) = entry

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        if len(keys) > 1:
            textui.print_dashed(
                'Created %s "%s" in %s "%s".' % (
                    self.obj.object_name, keys[1], self.obj.parent_object_name,
                    keys[0]
                )
            )
        else:
            textui.print_dashed(
                'Created %s "%s".' % (self.obj.object_name, keys[0])
            )

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn


class LDAPRetrieve(crud.Retrieve):
    """
    Retrieve an LDAP entry.
    """
    takes_options = (
        Flag('all',
            cli_name='all',
            doc='retrieve all attributes',
        ),
    )

    def get_args(self):
        if self.obj.parent_key:
            yield self.obj.parent_key.clone(query=True)
        yield self.obj.primary_key.clone(attribute=True, query=True)

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

        return (dn, entry_attrs)

    def output_for_cli(self, textui, entry, *keys, **options):
        (dn, entry_attrs) = entry

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, attrs_list, *keys, **options):
        return dn


class LDAPUpdate(crud.Update):
    """
    Update an LDAP entry.
    """
    def get_args(self):
        if self.obj.parent_key:
            yield self.obj.parent_key.clone(query=True)
        yield self.obj.primary_key.clone(attribute=True, query=True)

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

        return (dn, entry_attrs)

    def output_for_cli(self, textui, entry, *keys, **options):
        (dn, entry_attrs) = entry

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        if len(keys) > 1:
            textui.print_dashed(
                'Modified %s "%s" in %s "%s".' % (
                    self.obj.object_name, keys[1], self.obj.parent_object_name,
                    keys[0]
                )
            )
        else:
            textui.print_dashed(
                'Modified %s "%s".' % (self.obj.object_name, keys[0])
            )

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn


class LDAPDelete(crud.Delete):
    """
    Delete an LDAP entry and all of its direct subentries.
    """
    def get_args(self):
        if self.obj.parent_key:
            yield self.obj.parent_key.clone(query=True)
        yield self.obj.primary_key.clone(attribute=True, query=True)

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
        else:
            textui.print_dashed(
                'Deleted %s "%s".' % (self.obj.object_name, keys[0])
            )

    def pre_callback(self, ldap, dn, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        return True


class LDAPSearch(crud.Search):
    """
    Retrieve all LDAP entries matching the given criteria.
    """
    takes_options = (
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

        base_dn = self.obj.container_dn
        if self.obj.parent_key:
            base_dn = ldap.make_dn_from_attr(
                self.obj.parent_key.name, args[0], base_dn
            )
            term = args[1]
        else:
            term = args[0]

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
                filter, attrs_list, base_dn
            )
        except errors.NotFound:
            (entries, truncated) = (tuple(), False)

        self.post_callback(self, ldap, entries, truncated, *args, **options)

        return (entries, truncated)

    def output_for_cli(self, textui, result, *args, **options):
        (entries, truncated) = result

        textui.print_name(self.name)
        for (dn, entry_attrs) in entries:
            textui.print_attribute('dn', dn)
            textui.print_entry(entry_attrs)
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

    def pre_callback(self, ldap, filter, attrs_list, base_dn, *args, **options):
        return filter

    def post_callback(self, ldap, entries, truncated, *args, **options):
        pass

