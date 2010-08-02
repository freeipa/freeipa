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

import re

from ipalib import crud, errors, uuid
from ipalib import Method, Object
from ipalib import Flag, List, Str
from ipalib.base import NameSpace
from ipalib.cli import to_cli, from_cli
from ipalib import output
from ipalib.text import _


def validate_add_attribute(ugettext, attr):
    validate_attribute(ugettext, 'addattr', attr)

def validate_set_attribute(ugettext, attr):
    validate_attribute(ugettext, 'setattr', attr)

def validate_attribute(ugettext, name, attr):
    m = re.match("\s*(.*?)\s*=\s*(.*?)\s*$", attr)
    if not m or len(m.groups()) != 2:
        raise errors.ValidationError(name=name, error='Invalid format. Should be name=value')

def get_attributes(attrs):
    """
    Given a list of values in the form name=value, return a list of name.
    """
    attrlist=[]
    for attr in attrs:
        m = re.match("\s*(.*?)\s*=\s*(.*?)\s*$", attr)
        attrlist.append(str(m.group(1)).lower())

    return attrlist


class LDAPObject(Object):
    """
    Object representing a LDAP entry.
    """
    backend_name = 'ldap2'

    parent_object = ''
    container_dn = ''
    normalize_dn = True
    object_name = 'entry'
    object_name_plural = 'entries'
    object_class = []
    object_class_config = None
    search_attributes = []
    search_attributes_config = None
    default_attributes = []
    hidden_attributes = ['objectclass', 'aci']
    uuid_attribute = ''
    attribute_members = {}

    container_not_found_msg = _('container entry (%(container)s) not found')
    parent_not_found_msg = _('%(parent)s: %(oname)s not found')
    object_not_found_msg = _('%(pkey)s: %(oname)s not found')

    def get_dn(self, *keys, **kwargs):
        if self.parent_object:
            parent_dn = self.api.Object[self.parent_object].get_dn(*keys[:-1])
        else:
            parent_dn = self.container_dn
        if self.primary_key and keys[-1] is not None:
            return self.backend.make_dn_from_attr(
                self.primary_key.name, keys[-1], parent_dn
            )
        return parent_dn

    def get_primary_key_from_dn(self, dn):
        return dn[len(self.primary_key.name) + 1:dn.find(',')]

    def get_ancestor_primary_keys(self):
        if self.parent_object:
            parent_obj = self.api.Object[self.parent_object]
            for key in parent_obj.get_ancestor_primary_keys():
                yield key
            if parent_obj.primary_key:
                yield parent_obj.primary_key.clone(query=True)

    def convert_attribute_members(self, entry_attrs, *keys, **options):
        if options.get('raw', False):
            return
        for attr in self.attribute_members:
            for member in entry_attrs.setdefault(attr, []):
                for ldap_obj_name in self.attribute_members[attr]:
                    ldap_obj = self.api.Object[ldap_obj_name]
                    if member.find(ldap_obj.container_dn) > 0:
                        new_attr = '%s_%s' % (attr, ldap_obj.object_name)
                        entry_attrs.setdefault(new_attr, []).append(
                            ldap_obj.get_primary_key_from_dn(member)
                        )
            del entry_attrs[attr]

    def handle_not_found(self, *keys):
        raise errors.NotFound(
            reason=self.object_not_found_msg % {
                'pkey': keys[-1], 'oname': self.object_name,
            }
        )


# Options used by create and update.
_attr_options = (
    Str('addattr*', validate_add_attribute,
        cli_name='addattr',
        doc=_('Add an attribute/value pair. Format is attr=value'),
        exclude='webui',
    ),
    Str('setattr*', validate_set_attribute,
        cli_name='setattr',
        doc=_('Set an attribute to an name/value pair. Format is attr=value'),
        exclude='webui',
    ),
)


class CallbackInterface(Method):
    """
    Callback registration interface
    """
    def __init__(self):
        if not hasattr(self.__class__, 'PRE_CALLBACKS'):
            self.__class__.PRE_CALLBACKS = []
        if not hasattr(self.__class__, 'POST_CALLBACKS'):
            self.__class__.POST_CALLBACKS = []
        if not hasattr(self.__class__, 'EXC_CALLBACKS'):
            self.__class__.EXC_CALLBACKS = []
        if hasattr(self, 'pre_callback'):
            self.register_pre_callback(self.pre_callback, True)
        if hasattr(self, 'post_callback'):
            self.register_post_callback(self.post_callback, True)
        if hasattr(self, 'exc_callback'):
            self.register_exc_callback(self.exc_callback, True)
        super(Method, self).__init__()

    @classmethod
    def register_pre_callback(klass, callback, first=False):
        assert callable(callback)
        if not hasattr(klass, 'PRE_CALLBACKS'):
            klass.PRE_CALLBACKS = []
        if first:
            klass.PRE_CALLBACKS.insert(0, callback)
        else:
            klass.PRE_CALLBACKS.append(callback)

    @classmethod
    def register_post_callback(klass, callback, first=False):
        assert callable(callback)
        if not hasattr(klass, 'POST_CALLBACKS'):
            klass.POST_CALLBACKS = []
        if first:
            klass.POST_CALLBACKS.insert(0, callback)
        else:
            klass.POST_CALLBACKS.append(callback)

    @classmethod
    def register_exc_callback(klass, callback, first=False):
        assert callable(callback)
        if not hasattr(klass, 'EXC_CALLBACKS'):
            klass.EXC_CALLBACKS = []
        if first:
            klass.EXC_CALLBACKS.insert(0, callback)
        else:
            klass.EXC_CALLBACKS.append(callback)

    def _call_exc_callbacks(self, args, options, exc, call_func, *call_args, **call_kwargs):
        rv = None
        for i in xrange(len(getattr(self, 'EXC_CALLBACKS', []))):
            callback = self.EXC_CALLBACKS[i]
            try:
                if hasattr(callback, 'im_self'):
                    rv = callback(
                        args, options, exc, call_func, *call_args, **call_kwargs
                    )
                else:
                    rv = callback(
                        self, args, options, exc, call_func, *call_args,
                        **call_kwargs
                    )
            except errors.ExecutionError, e:
                if (i + 1) < len(self.EXC_CALLBACKS):
                    exc = e
                    continue
                raise e
        return rv


class LDAPCreate(CallbackInterface, crud.Create):
    """
    Create a new entry in LDAP.
    """
    takes_options = _attr_options

    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key
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

        if self.obj.uuid_attribute:
            entry_attrs[self.obj.uuid_attribute] = str(uuid.uuid1())

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = list(
                set(self.obj.default_attributes + entry_attrs.keys())
            )

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(
                    ldap, dn, entry_attrs, attrs_list, *keys, **options
                )
            else:
                dn = callback(
                    self, ldap, dn, entry_attrs, attrs_list, *keys, **options
                )

        try:
            ldap.add_entry(dn, entry_attrs, normalize=self.obj.normalize_dn)
        except errors.ExecutionError, e:
            try:
                self._call_exc_callbacks(
                    keys, options, e, ldap.add_entry, dn, entry_attrs,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                parent = self.obj.parent_object
                if parent:
                    raise errors.NotFound(
                        reason=self.obj.parent_not_found_msg % {
                            'parent': keys[-2],
                            'oname': self.api.Object[parent].object_name,
                        }
                    )
                raise errors.NotFound(
                    reason=self.obj.container_not_found_msg % {
                        'container': self.obj.container_dn,
                    }
                )

        try:
            (dn, entry_attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
        except errors.ExecutionError, e:
            try:
                (dn, entry_attrs) = self._call_exc_callbacks(
                    keys, options, e, ldap.get_entry, dn, attrs_list,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                self.obj.handle_not_found(*keys)

        for callback in self.POST_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, entry_attrs, *keys, **options)
            else:
                dn = callback(self, ldap, dn, entry_attrs, *keys, **options)

        entry_attrs['dn'] = dn

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        if self.obj.primary_key and keys[-1] is not None:
            return dict(result=entry_attrs, value=keys[-1])
        return dict(result=entry_attrs, value=u'')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPQuery(CallbackInterface, crud.PKQuery):
    """
    Base class for commands that need to retrieve an existing entry.
    """
    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        if self.obj.primary_key:
            yield self.obj.primary_key.clone(attribute=True, query=True)


class LDAPRetrieve(LDAPQuery):
    """
    Retrieve an LDAP entry.
    """
    has_output = output.standard_entry

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = list(self.obj.default_attributes)

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, attrs_list, *keys, **options)
            else:
                dn = callback(self, ldap, dn, attrs_list, *keys, **options)

        try:
            (dn, entry_attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
        except errors.ExecutionError, e:
            try:
                (dn, entry_attrs) = self._call_exc_callbacks(
                    keys, options, e, ldap.get_entry, dn, attrs_list,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                self.obj.handle_not_found(*keys)

        for callback in self.POST_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, entry_attrs, *keys, **options)
            else:
                dn = callback(self, ldap, dn, entry_attrs, *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        entry_attrs['dn'] = dn
        if self.obj.primary_key and keys[-1] is not None:
            return dict(result=entry_attrs, value=keys[-1])
        return dict(result=entry_attrs, value=u'')

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPUpdate(LDAPQuery, crud.Update):
    """
    Update an LDAP entry.
    """

    takes_options = _attr_options

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        if len(options) == 2: # 'all' and 'raw' are always sent
            raise errors.EmptyModlist()

        dn = self.obj.get_dn(*keys, **options)

        entry_attrs = self.args_options_2_entry(**options)

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = list(
                set(self.obj.default_attributes + entry_attrs.keys())
            )

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(
                    ldap, dn, entry_attrs, attrs_list, *keys, **options
                )
            else:
                dn = callback(
                    self, ldap, dn, entry_attrs, attrs_list, *keys, **options
                )

        """
        Some special handling is needed because we need to update the
        values here rather than letting ldap.update_entry() do the work. We
        have to do the work of adding new values to an existing attribute
        because if we pass just what is addded only the new values get
        set.
        """
        if 'addattr' in options:
            try:
                (dn, old_entry) = ldap.get_entry(
                    dn, attrs_list, normalize=self.obj.normalize_dn
                )
            except errors.ExecutionError, e:
                try:
                    (dn, old_entry) = self._call_exc_callbacks(
                        keys, options, e, ldap.get_entry, dn, attrs_list,
                        normalize=self.obj.normalize_dn
                    )
                except errors.NotFound:
                    self.obj.handle_not_found(*keys)
            attrlist = get_attributes(options['addattr'])
            for attr in attrlist:
                if attr in old_entry:
                    if type(entry_attrs[attr]) in (tuple,list):
                        entry_attrs[attr] = old_entry[attr] + entry_attrs[attr]
                    else:
                        old_entry[attr].append(entry_attrs[attr])
                        entry_attrs[attr] = old_entry[attr]

        try:
            ldap.update_entry(dn, entry_attrs, normalize=self.obj.normalize_dn)
        except errors.ExecutionError, e:
            try:
                self._call_exc_callbacks(
                    keys, options, e, ldap.update_entry, dn, entry_attrs,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                self.obj.handle_not_found(*keys)

        try:
            (dn, entry_attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
        except errors.ExecutionError, e:
            try:
                (dn, entry_attrs) = self._call_exc_callbacks(
                    keys, options, e, ldap.get_entry, dn, attrs_list,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                raise errors.MidairCollision(
                    format=_('the entry was deleted while being modified')
                )

        for callback in self.POST_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, entry_attrs, *keys, **options)
            else:
                dn = callback(self, ldap, dn, entry_attrs, *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        if self.obj.primary_key and keys[-1] is not None:
            return dict(result=entry_attrs, value=keys[-1])
        return dict(result=entry_attrs, value=u'')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPDelete(LDAPQuery):
    """
    Delete an LDAP entry and all of its direct subentries.
    """
    has_output = output.standard_delete

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, *keys, **options)
            else:
                dn = callback(self, ldap, dn, *keys, **options)

        def delete_subtree(base_dn):
            truncated = True
            while truncated:
                try:
                    (subentries, truncated) = ldap.find_entries(
                        None, [''], base_dn, ldap.SCOPE_ONELEVEL
                    )
                except errors.NotFound:
                    break
                else:
                    for (dn_, entry_attrs) in subentries:
                        delete_subtree(dn_)
            try:
                ldap.delete_entry(base_dn, normalize=self.obj.normalize_dn)
            except errors.ExecutionError, e:
                try:
                    self._call_exc_callbacks(
                        keys, options, e, ldap.delete_entry, base_dn,
                        normalize=self.obj.normalize_dn
                    )
                except errors.NotFound:
                    self.obj.handle_not_found(*keys)

        delete_subtree(dn)

        for callback in self.POST_CALLBACKS:
            if hasattr(callback, 'im_self'):
                result = callback(ldap, dn, *keys, **options)
            else:
                result = callback(self, ldap, dn, *keys, **options)

        if self.obj.primary_key and keys[-1] is not None:
            return dict(result=result, value=keys[-1])
        return dict(result=result, value=u'')

    def pre_callback(self, ldap, dn, *keys, **options):
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        return True

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPModMember(LDAPQuery):
    """
    Base class for member manipulation.
    """
    member_attributes = ['member']
    member_param_doc = 'comma-separated list of %s'
    member_count_out = ('%i member processed.', '%i members processed.')

    def get_options(self):
        for option in super(LDAPModMember, self).get_options():
            yield option
        for attr in self.member_attributes:
            for ldap_obj_name in self.obj.attribute_members[attr]:
                ldap_obj = self.api.Object[ldap_obj_name]
                name = to_cli(ldap_obj_name)
                doc = self.member_param_doc % ldap_obj.object_name_plural
                yield List('%s?' % name, cli_name='%ss' % name, doc=doc,
                           label=ldap_obj.object_name_plural)

    def get_member_dns(self, **options):
        dns = {}
        failed = {}
        for attr in self.member_attributes:
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


class LDAPAddMember(LDAPModMember):
    """
    Add other LDAP entries to members.
    """
    member_param_doc = 'comma-separated list of %s to add'
    member_count_out = ('%i member added.', '%i members added.')

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of members added'),
        ),
    )

    has_output_params = (
        Str('member',
            label=_('Failed members'),
        ),
    )

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        (member_dns, failed) = self.get_member_dns(**options)

        dn = self.obj.get_dn(*keys, **options)

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, member_dns, failed, *keys, **options)
            else:
                dn = callback(
                    self, ldap, dn, member_dns, failed, *keys, **options
                )

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

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = list(
                set(self.obj.default_attributes + member_dns.keys())
            )

        try:
            (dn, entry_attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
        except errors.ExecutionError, e:
            try:
                (dn, entry_attrs) = self._call_exc_callbacks(
                    keys, options, e, ldap.get_entry, dn, attrs_list,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                self.obj.handle_not_found(*keys)

        for callback in self.POST_CALLBACKS:
            if hasattr(callback, 'im_self'):
                (completed, dn) = callback(
                    ldap, completed, failed, dn, entry_attrs, *keys, **options
                )
            else:
                (completed, dn) = callback(
                    self, ldap, completed, failed, dn, entry_attrs, *keys,
                    **options
                )

        entry_attrs['dn'] = dn
        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        return dict(
            completed=completed,
            failed=failed,
            result=entry_attrs,
        )

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        return (completed, dn)

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPRemoveMember(LDAPModMember):
    """
    Remove LDAP entries from members.
    """
    member_param_doc = 'comma-separated list of %s to remove'
    member_count_out = ('%i member removed.', '%i members removed.')

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be removed'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of members removed'),
        ),
    )

    has_output_params = (
        Str('member',
            label=_('Failed members'),
        ),
    )

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        (member_dns, failed) = self.get_member_dns(**options)

        dn = self.obj.get_dn(*keys, **options)

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, member_dns, failed, *keys, **options)
            else:
                dn = callback(
                    self, ldap, dn, member_dns, failed, *keys, **options
                )

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

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = list(
                set(self.obj.default_attributes + member_dns.keys())
            )

        try:
            (dn, entry_attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
        except errors.ExecutionError, e:
            try:
                (dn, entry_attrs) = self._call_exc_callbacks(
                    keys, options, e, ldap.get_entry, dn, attrs_list,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                self.obj.handle_not_found(*keys)

        for callback in self.POST_CALLBACKS:
            if hasattr(callback, 'im_self'):
                (completed, dn) = callback(
                    ldap, completed, failed, dn, entry_attrs, *keys, **options
                )
            else:
                (completed, dn) = callback(
                    self, ldap, completed, failed, dn, entry_attrs, *keys,
                    **options
                )

        entry_attrs['dn'] = dn

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)
        return dict(
            completed=completed,
            failed=failed,
            result=entry_attrs,
        )

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        return (completed, dn)

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPSearch(CallbackInterface, crud.Search):
    """
    Retrieve all LDAP entries matching the given criteria.
    """
    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        yield Str('criteria?')

    def get_options(self):
        for option in super(LDAPSearch, self).get_options():
            yield option

    def execute(self, *args, **options):
        ldap = self.obj.backend

        term = args[-1]
        if self.obj.parent_object:
            base_dn = self.api.Object[self.obj.parent_object].get_dn(*args[:-1])
        else:
            base_dn = self.obj.container_dn

        search_kw = self.args_options_2_entry(**options)

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = list(
                set(self.obj.default_attributes + search_kw.keys())
            )

        if self.obj.search_attributes:
            search_attrs = self.obj.search_attributes
        else:
            search_attrs = self.obj.default_attributes
        if self.obj.search_attributes_config:
            config = ldap.get_ipa_config()[1]
            config_attrs = config.get(
                self.obj.search_attributes_config, [])
            if len(config_attrs) == 1 and (
                isinstance(config_attrs[0], basestring)):
                search_attrs = config_attrs[0].split(',')

        search_kw['objectclass'] = self.obj.object_class
        attr_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)

        search_kw = {}
        for a in search_attrs:
            search_kw[a] = term
        term_filter = ldap.make_filter(search_kw, exact=False)

        filter = ldap.combine_filters(
            (term_filter, attr_filter), rules=ldap.MATCH_ALL
        )

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                filter = callback(
                    ldap, filter, attrs_list, base_dn, *args, **options
                )
            else:
                filter = callback(
                    self, ldap, filter, attrs_list, base_dn, *args, **options
                )

        try:
            (entries, truncated) = ldap.find_entries(
                filter, attrs_list, base_dn, scope=ldap.SCOPE_ONELEVEL
            )
        except errors.ExecutionError, e:
            try:
                (entries, truncated) = self._call_exc_callbacks(
                    args, options, e, ldap.find_entries, filter, attrs_list,
                    base_dn, scoope=ldap.SCOPE_ONELEVEL,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                (entries, truncated) = ([], False)

        for callback in self.POST_CALLBACKS:
            if hasattr(callback, 'im_self'):
                callback(ldap, entries, truncated, *args, **options)
            else:
                callback(self, ldap, entries, truncated, *args, **options)

        if not options.get('raw', False):
            for e in entries:
                self.obj.convert_attribute_members(e[1], *args, **options)

        for e in entries:
            e[1]['dn'] = e[0]
        entries = [e for (dn, e) in entries]

        return dict(
            result=entries,
            count=len(entries),
            truncated=truncated,
        )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, *args, **options):
        return filter

    def post_callback(self, ldap, entries, truncated, *args, **options):
        pass

    def exc_callback(self, args, options, exc, call_func, *call_args, **call_kwargs):
        raise exc

