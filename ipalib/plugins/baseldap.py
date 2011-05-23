# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
"""
Base classes for LDAP plugins.
"""

import re
import json
import time
from copy import deepcopy

from ipalib import api, crud, errors
from ipalib import Method, Object
from ipalib import Flag, Int, List, Str
from ipalib.base import NameSpace
from ipalib.cli import to_cli, from_cli
from ipalib import output
from ipalib.text import _
from ipalib.util import json_serialize

global_output_params = (
    Str('member',
        label=_('Failed members'),
    ),
    Str('member_user?',
        label=_('Member users'),
    ),
    Str('member_group?',
        label=_('Member groups'),
    ),
    Str('memberof_group?',
        label=_('Member of groups'),
    ),
    Str('member_host?',
        label=_('Member hosts'),
    ),
    Str('member_hostgroup?',
        label=_('Member host-groups'),
    ),
    Str('memberof_hostgroup?',
        label=_('Member of host-groups'),
    ),
    Str('memberof_permission?',
        label=_('Permissions'),
    ),
    Str('memberof_privilege?',
        label='Privileges',
    ),
    Str('memberof_role?',
        label=_('Roles'),
    ),
    Str('memberof_sudocmdgroup?',
        label=_('Sudo Command Groups'),
    ),
    Str('member_privilege?',
        label='Granted to Privilege',
    ),
    Str('member_role?',
        label=_('Granting privilege to roles'),
    ),
    Str('member_netgroup?',
        label=_('Member netgroups'),
    ),
    Str('memberof_netgroup?',
        label=_('Member of netgroups'),
    ),
    Str('member_service?',
        label=_('Member services'),
    ),
    Str('member_servicegroup?',
        label=_('Member service groups'),
    ),
    Str('memberof_servicegroup?',
        label='Member of service groups',
    ),
    Str('member_hbacsvcgroup?',
        label=_('Member HBAC service groups'),
    ),
    Str('memberof_hbacsvcgroup?',
        label='Member of HBAC service groups',
    ),
    Str('member_sudocmd?',
        label='Member Sudo commands',
    ),
    Str('memberindirect_user?',
        label=_('Indirect Member users'),
    ),
    Str('memberindirect_group?',
        label=_('Indirect Member groups'),
    ),
    Str('memberindirect_host?',
        label=_('Indirect Member hosts'),
    ),
    Str('memberindirect_hostgroup?',
        label=_('Indirect Member host-groups'),
    ),
    Str('memberindirect_role?',
        label=_('Indirect Member of roles'),
    ),
    Str('memberindirect_permission?',
        label=_('Indirect Member permissions'),
    ),
    Str('memberindirect_hbacsvc?',
        label=_('Indirect Member HBAC service'),
    ),
    Str('memberindirect_hbacsvcgrp?',
        label=_('Indirect Member HBAC service group'),
    ),
    Str('memberindirect_netgroup?',
        label=_('Indirect Member netgroups'),
    ),
    Str('memberofindirect_group?',
        label='Indirect Member of group',
    ),
    Str('memberofindirect_netgroup?',
        label='Indirect Member of netgroup',
    ),
    Str('memberofindirect_hostgroup?',
        label='Indirect Member of host-group',
    ),
    Str('memberofindirect_role?',
        label='Indirect Member of role',
    ),
    Str('externalhost?',
        label=_('External host'),
    ),
    Str('memberhost',
        label=_('Failed hosts/hostgroups'),
    ),
    Str('memberuser',
        label=_('Failed users/groups'),
    ),
    Str('managedby',
        label=_('Failed managedby'),
    ),
    Str('failed',
        label=_('Failed to remove'),
        flags=['suppress_empty'],
    ),
)


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
    if attrs:
        for attr in attrs:
            m = re.match("\s*(.*?)\s*=\s*(.*?)\s*$", attr)
            attrlist.append(str(m.group(1)).lower())
    return attrlist


def get_effective_rights(ldap, dn, attrs=None):
    if attrs is None:
        attrs = ['*', 'nsaccountlock', 'cospriority']
    rights = ldap.get_effective_rights(dn, attrs)
    rdict = {}
    if 'attributelevelrights' in rights[1]:
        rights = rights[1]['attributelevelrights']
        rights = rights[0].split(', ')
        for r in rights:
            (k,v) = r.split(':')
            rdict[k.strip().lower()] = v

    return rdict

def wait_for_memberof(keys, entry_start, completed, show_command, adding=True):
    """
    When adding or removing reverse members we are faking an update to
    object A by updating the member attribute in object B. The memberof
    plugin makes this work by adding or removing the memberof attribute
    to/from object A, it just takes a little bit of time.

    This will loop for 6+ seconds, retrieving object A so we can see
    if all the memberof attributes have been updated.
    """
    if completed == 0:
        # nothing to do
        return api.Command[show_command](keys[-1])['result']

    if 'memberof' in entry_start:
        starting_memberof = len(entry_start['memberof'])
    else:
        starting_memberof = 0

    # Loop a few times to give the memberof plugin a chance to add the
    # entries. Don't sleep for more than 6 seconds.
    memberof = 0
    x = 0
    while x < 20:
        # sleep first because the first search, even on a quiet system,
        # almost always fails to have memberof set.
        time.sleep(.3)
        x = x + 1

        # FIXME: put a try/except around here? I think it is probably better
        # to just let the exception filter up to the caller.
        entry_attrs = api.Command[show_command](keys[-1])['result']
        if 'memberof' in entry_attrs:
            memberof = len(entry_attrs['memberof'])

        if adding:
            if starting_memberof + completed >= memberof:
                break
        else:
            if starting_memberof + completed <= memberof:
                break

    return entry_attrs

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
    # If an objectclass is possible but not default in an entry. Needed for
    # collecting attributes for ACI UI.
    possible_objectclasses = []
    limit_object_classes = [] # Only attributes in these are allowed
    disallow_object_classes = [] # Disallow attributes in these
    search_attributes = []
    search_attributes_config = None
    default_attributes = []
    search_display_attributes = [] # attributes displayed in LDAPSearch
    hidden_attributes = ['objectclass', 'aci']
    # set rdn_attribute only if RDN attribute differs from primary key!
    rdn_attribute = ''
    uuid_attribute = ''
    attribute_members = {}
    rdnattr = None
    # Can bind as this entry (has userPassword or krbPrincipalKey)
    bindable = False
    relationships = {
        # attribute: (label, inclusive param prefix, exclusive param prefix)
        'member': ('Member', '', 'no_'),
        'memberof': ('Member Of', 'in_', 'not_in_'),
        'memberindirect': (
            'Indirect Member', None, 'no_indirect_'
        ),
    }
    label = _('Entry')

    container_not_found_msg = _('container entry (%(container)s) not found')
    parent_not_found_msg = _('%(parent)s: %(oname)s not found')
    object_not_found_msg = _('%(pkey)s: %(oname)s not found')
    already_exists_msg = _('%(oname)s with name "%(pkey)s" already exists')

    def get_dn(self, *keys, **kwargs):
        if self.parent_object:
            parent_dn = self.api.Object[self.parent_object].get_dn(*keys[:-1])
        else:
            parent_dn = self.container_dn
        if self.rdn_attribute:
            try:
                (dn, entry_attrs) = self.backend.find_entry_by_attr(
                    self.primary_key.name, keys[-1], self.object_class, [''],
                    self.container_dn
                )
            except errors.NotFound:
                pass
            else:
                return dn
        if self.primary_key and keys[-1] is not None:
            return self.backend.make_dn_from_attr(
                self.primary_key.name, keys[-1], parent_dn
            )
        return parent_dn

    def get_primary_key_from_dn(self, dn):
        try:
            if self.rdn_attribute:
                (dn, entry_attrs) = self.backend.get_entry(
                    dn, [self.primary_key.name]
                )
                try:
                    return entry_attrs[self.primary_key.name][0]
                except (KeyError, IndexError):
                    return ''
        except errors.NotFound:
            pass
        return dn[len(self.primary_key.name) + 1:dn.find(',')]

    def get_ancestor_primary_keys(self):
        if self.parent_object:
            parent_obj = self.api.Object[self.parent_object]
            for key in parent_obj.get_ancestor_primary_keys():
                yield key
            if parent_obj.primary_key:
                pkey = parent_obj.primary_key
                yield pkey.__class__(
                    parent_obj.name + pkey.name, required=True, query=True,
                    cli_name=parent_obj.name, label=pkey.label
                )

    def has_objectclass(self, classes, objectclass):
        oc = map(lambda x:x.lower(),classes)
        return objectclass.lower() in oc

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
        pkey = ''
        if self.primary_key:
            pkey = keys[-1]
        raise errors.NotFound(
            reason=self.object_not_found_msg % {
                'pkey': pkey, 'oname': self.object_name,
            }
        )

    def handle_duplicate_entry(self, *keys):
        pkey = ''
        if self.primary_key:
            pkey = keys[-1]
        raise errors.DuplicateEntry(
            message=self.already_exists_msg % {
                'pkey': pkey, 'oname': self.object_name,
            }
        )

    # list of attributes we want exported to JSON
    json_friendly_attributes = (
        'parent_object', 'container_dn', 'object_name', 'object_name_plural',
        'object_class', 'object_class_config', 'default_attributes', 'label',
        'hidden_attributes', 'uuid_attribute', 'attribute_members', 'name',
        'takes_params', 'rdn_attribute', 'bindable', 'relationships',
    )

    def __json__(self):
        ldap = self.backend
        json_dict = dict(
            (a, getattr(self, a)) for a in self.json_friendly_attributes
        )
        if self.primary_key:
            json_dict['primary_key'] = self.primary_key.name
        objectclasses = self.object_class
        if self.object_class_config:
            config = ldap.get_ipa_config()[1]
            objectclasses = config.get(
                self.object_class_config, objectclasses
            )
        objectclasses += self.possible_objectclasses
        # Get list of available attributes for this object for use
        # in the ACI UI.
        attrs = self.api.Backend.ldap2.schema.attribute_types(objectclasses)
        attrlist = []
        # Go through the MUST first
        for (oid, attr) in attrs[0].iteritems():
            attrlist.append(attr.names[0].lower())
        # And now the MAY
        for (oid, attr) in attrs[1].iteritems():
            attrlist.append(attr.names[0].lower())
        json_dict['aciattrs'] = attrlist
        attrlist.sort()
        json_dict['methods'] = [m for m in self.methods]
        return json_dict


# Options used by create and update.
_attr_options = (
    Str('addattr*', validate_add_attribute,
        cli_name='addattr',
        doc=_('Add an attribute/value pair. Format is attr=value. The attribute must be part of the schema.'),
        exclude='webui',
    ),
    Str('setattr*', validate_set_attribute,
        cli_name='setattr',
        doc=_("""Set an attribute to a name/value pair. Format is attr=value.
For multi-valued attributes, the command replaces the values already present."""),
        exclude='webui',
    ),
)

# addattr can cause parameters to have more than one value even if not defined
# as multivalue, make sure this isn't the case
def _check_single_value_attrs(params, entry_attrs):
    for (a, v) in entry_attrs.iteritems():
        if isinstance(v, (list, tuple)) and len(v) > 1:
            if a in params and not params[a].multivalue:
                raise errors.OnlyOneValueAllowed(attr=a)

# setattr or --option='' can cause parameters to be empty that are otherwise
# required, make sure we enforce that.
def _check_empty_attrs(params, entry_attrs):
    for (a, v) in entry_attrs.iteritems():
        if v is None or (isinstance(v, basestring) and len(v) == 0):
            if a in params and params[a].required:
                raise errors.RequirementError(name=a)


def _check_limit_object_class(attributes, attrs, allow_only):
    """
    If the set of objectclasses is limited enforce that only those
    are updated in entry_attrs (plus dn)

    allow_only tells us what mode to check in:

    If True then we enforce that the attributes must be in the list of
    allowed.

    If False then those attributes are not allowed.
    """
    if len(attributes[0]) == 0 and len(attributes[1]) == 0:
        return
    limitattrs = deepcopy(attrs)
    # Go through the MUST first
    for (oid, attr) in attributes[0].iteritems():
        if attr.names[0].lower() in limitattrs:
            if not allow_only:
                raise errors.ObjectclassViolation(info='attribute "%(attribute)s" not allowed' % dict(attribute=attr.names[0].lower()))
            limitattrs.remove(attr.names[0].lower())
    # And now the MAY
    for (oid, attr) in attributes[1].iteritems():
        if attr.names[0].lower() in limitattrs:
            if not allow_only:
                raise errors.ObjectclassViolation(info='attribute "%(attribute)s" not allowed' % dict(attribute=attr.names[0].lower()))
            limitattrs.remove(attr.names[0].lower())
    if len(limitattrs) > 0 and allow_only:
        raise errors.ObjectclassViolation(info='attribute "%(attribute)s" not allowed' % dict(attribute=limitattrs[0]))

class CallbackInterface(Method):
    """
    Callback registration interface
    """
    def __init__(self):
        #pylint: disable=E1003
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
        #pylint: disable=E1003
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        if self.obj.primary_key:
            yield self.obj.primary_key.clone(attribute=True)
        for arg in super(crud.Create, self).get_args():
            yield arg

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        entry_attrs = self.args_options_2_entry(*keys, **options)
        entry_attrs['objectclass'] = deepcopy(self.obj.object_class)

        if self.obj.object_class_config:
            config = ldap.get_ipa_config()[1]
            entry_attrs['objectclass'] = config.get(
                self.obj.object_class_config, entry_attrs['objectclass']
            )

        if self.obj.uuid_attribute:
            entry_attrs[self.obj.uuid_attribute] = 'autogenerate'

        dn = self.obj.get_dn(*keys, **options)
        if self.obj.rdn_attribute:
            if not dn.startswith('%s=' % self.obj.primary_key.name):
                self.obj.handle_duplicate_entry(*keys)
            dn = ldap.make_dn(
                entry_attrs, self.obj.rdn_attribute, self.obj.container_dn
            )

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
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

        _check_single_value_attrs(self.params, entry_attrs)
        ldap.get_schema()
        _check_limit_object_class(self.api.Backend.ldap2.schema.attribute_types(self.obj.limit_object_classes), entry_attrs.keys(), allow_only=True)
        _check_limit_object_class(self.api.Backend.ldap2.schema.attribute_types(self.obj.disallow_object_classes), entry_attrs.keys(), allow_only=False)

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
            except errors.DuplicateEntry:
                self.obj.handle_duplicate_entry(*keys)

        try:
            if self.obj.rdn_attribute:
                (dn, entry_attrs) = ldap.find_entry_by_attr(
                    self.obj.primary_key.name, keys[-1], None, attrs_list,
                    self.obj.container_dn
                )
            else:
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

    # list of attributes we want exported to JSON
    json_friendly_attributes = (
        'takes_options',
    )

    def __json__(self):
        json_dict = dict(
            (a, getattr(self, a)) for a in self.json_friendly_attributes
        )
        return json_dict

class LDAPQuery(CallbackInterface, crud.PKQuery):
    """
    Base class for commands that need to retrieve an existing entry.
    """
    def get_args(self):
        #pylint: disable=E1003
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        if self.obj.primary_key:
            yield self.obj.primary_key.clone(attribute=True, query=True)
        for arg in super(crud.PKQuery, self).get_args():
            yield arg


class LDAPMultiQuery(LDAPQuery):
    """
    Base class for commands that need to retrieve one or more existing entries.
    """
    takes_options = (
        Flag('continue',
            cli_name='continue',
            doc=_('Continuous mode: Don\'t stop on errors.'),
        ),
    )

    def get_args(self):
        #pylint: disable=E1003
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        if self.obj.primary_key:
            yield self.obj.primary_key.clone(
                attribute=True, query=True, multivalue=True
            )
        for arg in super(crud.PKQuery, self).get_args():
            yield arg


class LDAPRetrieve(LDAPQuery):
    """
    Retrieve an LDAP entry.
    """
    has_output = output.standard_entry
    has_output_params = global_output_params

    takes_options = (
        Flag('rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
        ),
    )

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
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

        if options.get('rights', False) and options.get('all', False):
            entry_attrs['attributelevelrights'] = get_effective_rights(ldap, dn)

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

    takes_options = _attr_options + (
        Flag('rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
        ),
    )

    has_output_params = global_output_params

    def _get_rename_option(self):
        rdnparam = getattr(self.obj.params, self.obj.rdnattr)
        return rdnparam.clone_rename('rename',
            cli_name='rename', required=False, label=_('Rename'),
            doc=_('Rename the %(ldap_obj_name)s object') % dict(
                ldap_obj_name=self.obj.object_name
            )
        )

    def get_options(self):
        for option in super(LDAPUpdate, self).get_options():
            yield option
        if self.obj.rdnattr:
            yield self._get_rename_option()

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        if len(options) == 2: # 'all' and 'raw' are always sent
            raise errors.EmptyModlist()

        dn = self.obj.get_dn(*keys, **options)

        entry_attrs = self.args_options_2_entry(**options)

        """
        Some special handling is needed because we need to update the
        values here rather than letting ldap.update_entry() do the work. We
        have to do the work of adding new values to an existing attribute
        because if we pass just what is addded only the new values get
        set.
        """
        if 'addattr' in options:
            setset = set(get_attributes(options.get('setattr', [])))
            addset = set(get_attributes(options.get('addattr', [])))
            difflist = list(addset.difference(setset))
            if difflist:
                try:
                    (dn, old_entry) = ldap.get_entry(
                        dn, difflist, normalize=self.obj.normalize_dn
                    )
                except errors.ExecutionError, e:
                    try:
                        (dn, old_entry) = self._call_exc_callbacks(
                            keys, options, e, ldap.get_entry, dn, [],
                            normalize=self.obj.normalize_dn
                        )
                    except errors.NotFound:
                        self.obj.handle_not_found(*keys)
                for a in old_entry:
                    if not isinstance(entry_attrs[a], (list, tuple)):
                        entry_attrs[a] = [entry_attrs[a]]
                    entry_attrs[a] = list(entry_attrs[a]) + old_entry[a]

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
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

        _check_single_value_attrs(self.params, entry_attrs)
        _check_empty_attrs(self.obj.params, entry_attrs)
        ldap.get_schema()
        _check_limit_object_class(self.api.Backend.ldap2.schema.attribute_types(self.obj.limit_object_classes), entry_attrs.keys(), allow_only=True)
        _check_limit_object_class(self.api.Backend.ldap2.schema.attribute_types(self.obj.disallow_object_classes), entry_attrs.keys(), allow_only=False)

        rdnupdate = False
        try:
            if self.obj.rdnattr and 'rename' in options:
                if not options['rename']:
                    raise errors.ValidationError(name='rename', error=u'can\'t be empty')
                entry_attrs[self.obj.rdnattr] = options['rename']

            if self.obj.rdnattr and self.obj.rdnattr in entry_attrs:
                # RDN change
                ldap.update_entry_rdn(dn, unicode('%s=%s' % (self.obj.rdnattr,
                    entry_attrs[self.obj.rdnattr])))
                rdnkeys = keys[:-1] + (entry_attrs[self.obj.rdnattr], )
                dn = self.obj.get_dn(*rdnkeys)
                del entry_attrs[self.obj.rdnattr]
                options['rdnupdate'] = True
                rdnupdate = True

            ldap.update_entry(dn, entry_attrs, normalize=self.obj.normalize_dn)
        except errors.ExecutionError, e:
            # Exception callbacks will need to test for options['rdnupdate']
            # to decide what to do. An EmptyModlist in this context doesn't
            # mean an error occurred, just that there were no other updates to
            # perform.
            try:
                self._call_exc_callbacks(
                    keys, options, e, ldap.update_entry, dn, entry_attrs,
                    normalize=self.obj.normalize_dn
                )
            except errors.EmptyModlist, e:
                if not rdnupdate:
                    raise e
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

        if options.get('rights', False) and options.get('all', False):
            entry_attrs['attributelevelrights'] = get_effective_rights(ldap, dn)

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


class LDAPDelete(LDAPMultiQuery):
    """
    Delete an LDAP entry and all of its direct subentries.
    """
    has_output = output.standard_delete

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        def delete_entry(pkey):
            nkeys = keys[:-1] + (pkey, )
            dn = self.obj.get_dn(*nkeys, **options)

            for callback in self.PRE_CALLBACKS:
                if hasattr(callback, 'im_self'):
                    dn = callback(ldap, dn, *nkeys, **options)
                else:
                    dn = callback(self, ldap, dn, *nkeys, **options)

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
                            nkeys, options, e, ldap.delete_entry, base_dn,
                            normalize=self.obj.normalize_dn
                        )
                    except errors.NotFound:
                        self.obj.handle_not_found(*nkeys)

            delete_subtree(dn)

            for callback in self.POST_CALLBACKS:
                if hasattr(callback, 'im_self'):
                    result = callback(ldap, dn, *nkeys, **options)
                else:
                    result = callback(self, ldap, dn, *nkeys, **options)

            return result

        if not self.obj.primary_key or not isinstance(keys[-1], (list, tuple)):
            pkeyiter = (keys[-1], )
        else:
            pkeyiter = keys[-1]

        deleted = []
        failed = []
        result = True
        for pkey in pkeyiter:
            try:
                if not delete_entry(pkey):
                    result = False
            except errors.ExecutionError:
                if not options.get('continue', False):
                    raise
                failed.append(pkey)
            else:
                deleted.append(pkey)

        if self.obj.primary_key and pkeyiter[0] is not None:
            return dict(result=dict(failed=u','.join(failed)), value=u','.join(deleted))
        return dict(result=dict(failed=u''), value=u'')

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
                           label='member ' + ldap_obj.object_name, alwaysask=True)

    def get_member_dns(self, **options):
        dns = {}
        failed = {}
        for attr in self.member_attributes:
            dns[attr] = {}
            failed[attr] = {}
            for ldap_obj_name in self.obj.attribute_members[attr]:
                dns[attr][ldap_obj_name] = []
                failed[attr][ldap_obj_name] = []
                names = options.get(to_cli(ldap_obj_name), [])
                if not names:
                    continue
                for name in names:
                    if not name:
                        continue
                    ldap_obj = self.api.Object[ldap_obj_name]
                    try:
                        dns[attr][ldap_obj_name].append(ldap_obj.get_dn(name))
                    except errors.PublicError, e:
                        failed[attr][ldap_obj_name].append((name, unicode(e)))
        return (dns, failed)


class LDAPAddMember(LDAPModMember):
    """
    Add other LDAP entries to members.
    """
    member_param_doc = 'comma-separated list of %s to add'
    member_count_out = ('%i member added.', '%i members added.')
    allow_same = False

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

    has_output_params = global_output_params

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
                        ldap.add_entry_to_group(m_dn, dn, attr, allow_same=self.allow_same)
                    except errors.PublicError, e:
                        ldap_obj = self.api.Object[ldap_obj_name]
                        failed[attr][ldap_obj_name].append((
                            ldap_obj.get_primary_key_from_dn(m_dn),
                            unicode(e),)
                        )
                    else:
                        completed += 1

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
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

    has_output_params = global_output_params

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
                    except errors.PublicError, e:
                        ldap_obj = self.api.Object[ldap_obj_name]
                        failed[attr][ldap_obj_name].append((
                            ldap_obj.get_primary_key_from_dn(m_dn),
                            unicode(e),)
                        )
                    else:
                        completed += 1

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = list(
                set(self.obj.default_attributes + member_dns.keys())
            )

        # Give memberOf a chance to update entries
        time.sleep(.3)

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
    member_attributes = []
    member_param_incl_doc = 'Search for %s with these %s %s.'
    member_param_excl_doc = 'Search for %s without these %s %s.'

    takes_options = (
        Int('timelimit?',
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
        Int('sizelimit?',
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
    )

    def get_args(self):
        #pylint: disable=E1003
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        yield Str('criteria?')
        for arg in super(crud.Search, self).get_args():
            yield arg

    def get_options(self):
        for option in super(LDAPSearch, self).get_options():
            yield option
        for attr in self.member_attributes:
            for ldap_obj_name in self.obj.attribute_members[attr]:
                ldap_obj = self.api.Object[ldap_obj_name]
                relationship = self.obj.relationships.get(
                    attr, ['member', '', 'no_']
                )
                doc = self.member_param_incl_doc % (
                    self.obj.object_name_plural, relationship[0].lower(),
                    ldap_obj.object_name_plural
                )
                name = '%s%s' % (relationship[1], to_cli(ldap_obj_name))
                yield List(
                    '%s?' % name, cli_name='%ss' % name, doc=doc,
                    label=ldap_obj.object_name
                )
                doc = self.member_param_excl_doc % (
                    self.obj.object_name_plural, relationship[0].lower(),
                    ldap_obj.object_name_plural
                )
                name = '%s%s' % (relationship[2], to_cli(ldap_obj_name))
                yield List(
                    '%s?' % name, cli_name='%ss' % name, doc=doc,
                    label=ldap_obj.object_name
                )

    def get_member_filter(self, ldap, **options):
        filter = ''
        for attr in self.member_attributes:
            for ldap_obj_name in self.obj.attribute_members[attr]:
                ldap_obj = self.api.Object[ldap_obj_name]
                relationship = self.obj.relationships.get(
                    attr, ['member', '', 'no_']
                )
                param_name = '%s%s' % (relationship[1], to_cli(ldap_obj_name))
                if param_name in options:
                    dns = []
                    for pkey in options[param_name]:
                        dns.append(ldap_obj.get_dn(pkey))
                    flt = ldap.make_filter_from_attr(
                        attr, dns, ldap.MATCH_ALL
                    )
                    filter = ldap.combine_filters(
                        (filter, flt), ldap.MATCH_ALL
                    )
                param_name = '%s%s' % (relationship[2], to_cli(ldap_obj_name))
                if param_name in options:
                    dns = []
                    for pkey in options[param_name]:
                        dns.append(ldap_obj.get_dn(pkey))
                    flt = ldap.make_filter_from_attr(
                        attr, dns, ldap.MATCH_NONE
                    )
                    filter = ldap.combine_filters(
                        (filter, flt), ldap.MATCH_ALL
                    )
        return filter

    has_output_params = global_output_params

    def execute(self, *args, **options):
        ldap = self.obj.backend

        term = args[-1]
        if self.obj.parent_object:
            base_dn = self.api.Object[self.obj.parent_object].get_dn(*args[:-1])
        else:
            base_dn = self.obj.container_dn

        search_kw = self.args_options_2_entry(**options)

        if self.obj.search_display_attributes:
            defattrs = self.obj.search_display_attributes
        else:
            defattrs = self.obj.default_attributes
        if options.get('all', False):
            attrs_list = ['*'] + defattrs
        else:
            attrs_list = list(
                set(defattrs + search_kw.keys())
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

        member_filter = self.get_member_filter(ldap, **options)

        filter = ldap.combine_filters(
            (term_filter, attr_filter, member_filter), rules=ldap.MATCH_ALL
        )

        scope = ldap.SCOPE_ONELEVEL
        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                    (filter, base_dn, scope) = callback(
                        ldap, filter, attrs_list, base_dn, scope, *args, **options
                    )
            else:
                (filter, base_dn, scope) = callback(
                    self, ldap, filter, attrs_list, base_dn, scope, *args, **options
                )

        try:
            (entries, truncated) = ldap.find_entries(
                filter, attrs_list, base_dn, scope,
                time_limit=options.get('timelimit', None),
                size_limit=options.get('sizelimit', None)
            )
        except errors.ExecutionError, e:
            try:
                (entries, truncated) = self._call_exc_callbacks(
                    args, options, e, ldap.find_entries, filter, attrs_list,
                    base_dn, scope=ldap.SCOPE_ONELEVEL,
                    normalize=self.obj.normalize_dn
                )
            except errors.NotFound:
                (entries, truncated) = ([], False)

        for callback in self.POST_CALLBACKS:
            if hasattr(callback, 'im_self'):
                callback(ldap, entries, truncated, *args, **options)
            else:
                callback(self, ldap, entries, truncated, *args, **options)

        if self.obj.primary_key:
            sortfn=lambda x,y: cmp(x[1][self.obj.primary_key.name][0].lower(), y[1][self.obj.primary_key.name][0].lower())
            entries.sort(sortfn)

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

    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        return (filters, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        pass

    def exc_callback(self, args, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPModReverseMember(LDAPQuery):
    """
    Base class for reverse member manipulation.
    """
    reverse_attributes = ['member']
    reverse_param_doc = 'comma-separated list of %s'
    reverse_count_out = ('%i member processed.', '%i members processed.')

    has_output_params = global_output_params

    def get_options(self):
        for option in super(LDAPModReverseMember, self).get_options():
            yield option
        for attr in self.reverse_attributes:
            for ldap_obj_name in self.obj.reverse_members[attr]:
                ldap_obj = self.api.Object[ldap_obj_name]
                name = to_cli(ldap_obj_name)
                doc = self.reverse_param_doc % ldap_obj.object_name_plural
                yield List('%s?' % name, cli_name='%ss' % name, doc=doc,
                           label=ldap_obj.object_name, alwaysask=True)


class LDAPAddReverseMember(LDAPModReverseMember):
    """
    Add other LDAP entries to members in reverse.

    The call looks like "add A to B" but in fact executes
    add B to A to handle reverse membership.
    """
    member_param_doc = 'comma-separated list of %s to add'
    member_count_out = ('%i member added.', '%i members added.')

    show_command = None
    member_command = None
    reverse_attr = None
    member_attr = None

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

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        # Ensure our target exists
        result = self.api.Command[self.show_command](keys[-1])['result']
        dn = result['dn']

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, *keys, **options)
            else:
                dn = callback(
                    self, ldap, dn, *keys, **options
                )

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = self.obj.default_attributes

        # Pull the record as it is now so we can know how many members
        # there are.
        entry_start = self.api.Command[self.show_command](keys[-1])['result']
        completed = 0
        failed = {'member': {self.reverse_attr: []}}
        for attr in options.get(self.reverse_attr, []):
            try:
                options = {'%s' % self.member_attr: keys[-1]}
                try:
                    result = self.api.Command[self.member_command](attr, **options)
                    if result['completed'] == 1:
                        completed = completed + 1
                    else:
                        failed['member'][self.reverse_attr].append((attr, result['failed']['member'][self.member_attr][0][1]))
                except errors.ExecutionError, e:
                    try:
                        (dn, entry_attrs) = self._call_exc_callbacks(
                            keys, options, e, self.member_command, dn, attrs_list,
                            normalize=self.obj.normalize_dn
                        )
                    except errors.NotFound, e:
                        msg = str(e)
                        (attr, msg) = msg.split(':', 1)
                        failed['member'][self.reverse_attr].append((attr, unicode(msg.strip())))

            except errors.PublicError, e:
                failed['member'][self.reverse_attr].append((attr, unicode(msg)))

        # Wait for the memberof plugin to update the entry
        try:
            entry_attrs = wait_for_memberof(keys, entry_start, completed, self.show_command, adding=True)
        except Exception, e:
            raise errors.ReverseMemberError(verb=_('added'), exc=str(e))

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
        return dict(
            completed=completed,
            failed=failed,
            result=entry_attrs,
        )

    def pre_callback(self, ldap, dn, *keys, **options):
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        return (completed, dn)

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc

class LDAPRemoveReverseMember(LDAPModReverseMember):
    """
    Remove other LDAP entries from members in reverse.

    The call looks like "remove A from B" but in fact executes
    remove B from A to handle reverse membership.
    """
    member_param_doc = 'comma-separated list of %s to remove'
    member_count_out = ('%i member removed.', '%i members removed.')

    show_command = None
    member_command = None
    reverse_attr = None
    member_attr = None

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

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        # Ensure our target exists
        result = self.api.Command[self.show_command](keys[-1])['result']
        dn = result['dn']

        for callback in self.PRE_CALLBACKS:
            if hasattr(callback, 'im_self'):
                dn = callback(ldap, dn, *keys, **options)
            else:
                dn = callback(
                    self, ldap, dn, *keys, **options
                )

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = self.obj.default_attributes

        # Pull the record as it is now so we can know how many members
        # there are.
        entry_start = self.api.Command[self.show_command](keys[-1])['result']
        completed = 0
        failed = {'member': {self.reverse_attr: []}}
        for attr in options.get(self.reverse_attr, []):
            try:
                options = {'%s' % self.member_attr: keys[-1]}
                try:
                    result = self.api.Command[self.member_command](attr, **options)
                    if result['completed'] == 1:
                        completed = completed + 1
                    else:
                        failed['member'][self.reverse_attr].append((attr, result['failed']['member'][self.member_attr][0][1]))
                except errors.ExecutionError, e:
                    try:
                        (dn, entry_attrs) = self._call_exc_callbacks(
                            keys, options, e, self.member_command, dn, attrs_list,
                            normalize=self.obj.normalize_dn
                        )
                    except errors.NotFound, e:
                        msg = str(e)
                        (attr, msg) = msg.split(':', 1)
                        failed['member'][self.reverse_attr].append((attr, unicode(msg.strip())))

            except errors.PublicError, e:
                failed['member'][self.reverse_attr].append((attr, unicode(msg)))

        # Wait for the memberof plugin to update the entry
        try:
            entry_attrs = wait_for_memberof(keys, entry_start, completed, self.show_command, adding=False)
        except Exception, e:
            raise errors.ReverseMemberError(verb=_('removed'), exc=str(e))

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
        return dict(
            completed=completed,
            failed=failed,
            result=entry_attrs,
        )

    def pre_callback(self, ldap, dn, *keys, **options):
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        return (completed, dn)

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc
