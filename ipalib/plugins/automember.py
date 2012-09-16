# Authors:
#   Jr Aquino <jr.aquino@citrix.com>
#
# Copyright (C) 2011  Red Hat
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

from ipalib import api, errors
from ipalib import Str, StrEnum
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
from ipalib.request import context
import ldap as _ldap
from ipapython.dn import DN

__doc__ = _("""
Auto Membership Rule.

Bring clarity to the membership of hosts and users by configuring inclusive
or exclusive regex patterns, you can automatically assign a new entries into
a group or hostgroup based upon attribute information.

A rule is directly associated with a group by name, so you cannot create
a rule without an accompanying group or hostgroup.

A condition is a regular expression used by 389-ds to match a new incoming
entry with an automember rule. If it matches an inclusive rule then the
entry is added to the appropriate group or hostgroup.

A default group or hostgroup could be specified for entries that do not
match any rule. In case of user entries this group will be a fallback group
because all users are by default members of group specified in IPA config.


EXAMPLES:

 Add the initial group or hostgroup:
   ipa hostgroup-add --desc="Web Servers" webservers
   ipa group-add --desc="Developers" devel

 Add the initial rule:
   ipa automember-add --type=hostgroup webservers
   ipa automember-add --type=group devel

 Add a condition to the rule:
   ipa automember-add-condition --key=fqdn --type=hostgroup --inclusive-regex=^web[1-9]+\.example\.com webservers
   ipa automember-add-condition --key=manager --type=group --inclusive-regex=^uid=mscott devel

 Add an exclusive condition to the rule to prevent auto assignment:
   ipa automember-add-condition --key=fqdn --type=hostgroup --exclusive-regex=^web5\.example\.com webservers

 Add a host:
    ipa host-add web1.example.com

 Add a user:
    ipa user-add --first=Tim --last=User --password tuser1 --manager=mscott

 Verify automembership:
    ipa hostgroup-show webservers
      Host-group: webservers
      Description: Web Servers
      Member hosts: web1.example.com

    ipa group-show devel
      Group name: devel
      Description: Developers
      GID: 1004200000
      Member users: tuser

 Remove a condition from the rule:
   ipa automember-remove-condition --key=fqdn --type=hostgroup --inclusive-regex=^web[1-9]+\.example\.com webservers

 Modify the automember rule:
    ipa automember-mod

 Set the default (fallback) target group:
    ipa automember-default-group-set --default-group=webservers --type=hostgroup
    ipa automember-default-group-set --default-group=ipausers --type=group

 Remove the default (fallback) target group:
    ipa automember-default-group-remove --type=hostgroup
    ipa automember-default-group-remove --type=group

 Show the default (fallback) target group:
    ipa automember-default-group-show --type=hostgroup
    ipa automember-default-group-show --type=group

 Find all of the automember rules:
    ipa automember-find

 Display a automember rule:
    ipa automember-show --type=hostgroup webservers
    ipa automember-show --type=group devel

 Delete an automember rule:
    ipa automember-del --type=hostgroup webservers
    ipa automember-del --type=group devel
""")

# Options used by Condition Add and Remove.
INCLUDE_RE = 'automemberinclusiveregex'
EXCLUDE_RE = 'automemberexclusiveregex'

regex_attrs = (
    Str('automemberinclusiveregex*',
        cli_name='inclusive_regex',
        label=_('Inclusive Regex'),
        doc=_('Inclusive Regex'),
        csv=True,
        alwaysask=True,
    ),
    Str('automemberexclusiveregex*',
        cli_name='exclusive_regex',
        label=_('Exclusive Regex'),
        doc=_('Exclusive Regex'),
        csv=True,
        alwaysask=True,
    ),
    Str('key',
        label=_('Attribute Key'),
        doc=_('Attribute to filter via regex. For example fqdn for a host, or manager for a user'),
        flags=['no_create', 'no_update', 'no_search']
    ),
)

group_type = (
    StrEnum('type',
        label=_('Grouping Type'),
        doc=_('Grouping to which the rule applies'),
        values=(u'group', u'hostgroup', ),
    ),
)

automember_rule = (
    Str('cn',
        cli_name='automember_rule',
        label=_('Automember Rule'),
        doc=_('Automember Rule'),
        normalizer=lambda value: value.lower(),
    ),
)

class automember(LDAPObject):

    """
    Bring automember to a hostgroup with an Auto Membership Rule.
    """

    container_dn = api.env.container_automember

    object_name = 'auto_member_rule'
    object_name_plural = 'auto_member_rules'
    object_class = ['top', 'automemberregexrule']
    default_attributes = [
        'automemberinclusiveregex', 'automemberexclusiveregex',
        'cn', 'automembertargetgroup', 'description', 'automemberdefaultgroup'
    ]

    label = _('Auto Membership Rule')

    takes_params = (
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('A description of this auto member rule'),
        ),
        Str('automemberdefaultgroup?',
            cli_name='default_group',
            label=_('Default (fallback) Group'),
            doc=_('Default group for entries to land'),
            flags=['no_create', 'no_update', 'no_search']
        ),
    )

    def dn_exists(self, grouptype, groupname, *keys):
        ldap = self.api.Backend.ldap2
        dn = self.api.Object[grouptype].get_dn(groupname)
        try:
            (gdn, entry_attrs) = ldap.get_entry(dn, [])
        except errors.NotFound:
            raise errors.NotFound(reason=_(u'Group: %s not found!') % groupname)
        return gdn

    def get_dn(self, *keys, **options):
        if self.parent_object:
            parent_dn = self.api.Object[self.parent_object].get_dn(*keys[:-1])
        else:
            parent_dn = self.container_dn
        grouptype = options['type']
        try:
            ndn = DN(('cn', keys[-1]), ('cn', grouptype), parent_dn)
        except IndexError:
            ndn = DN(('cn', grouptype), parent_dn)
        return ndn

    def check_attr(self, attr):
        """
        Verify that the user supplied key is a valid attribute in the schema
        """
        ldap = self.api.Backend.ldap2
        obj = ldap.schema.get_obj(_ldap.schema.AttributeType, attr)
        if obj is not None:
            return obj
        else:
            raise errors.NotFound(reason=_('%s is not a valid attribute.') % attr)

api.register(automember)


def automember_container_exists(ldap):
    try:
        ldap.get_entry(api.env.container_automember, [])
    except errors.NotFound:
        return False
    return True

class automember_add(LDAPCreate):
    __doc__ = _("""
    Add an automember rule.
    """)
    takes_options = LDAPCreate.takes_options + group_type
    takes_args = automember_rule
    msg_summary = _('Added automember rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)

        entry_attrs['cn'] = keys[-1]
        if not automember_container_exists(self.api.Backend.ldap2):
            raise errors.NotFound(reason=_('Auto Membership is not configured'))
        entry_attrs['automembertargetgroup'] = self.obj.dn_exists(options['type'], keys[-1])
        return dn

    def execute(self, *keys, **options):
        result = super(automember_add, self).execute(*keys, **options)
        result['value'] = keys[-1]
        return result

api.register(automember_add)


class automember_add_condition(LDAPUpdate):
    __doc__ = _("""
    Add conditions to an automember rule.
    """)
    has_output_params = (
        Str('failed',
        label=_('Failed to add'),
        flags=['suppress_empty'],
        ),
    )

    takes_options = regex_attrs + group_type
    takes_args = automember_rule
    msg_summary = _('Added condition(s) to "%(value)s"')

    # Prepare the output to expect failed results
    has_output = (
        output.summary,
        output.Entry('result'),
        output.value,
        output.Output('failed',
            type=dict,
            doc=_('Conditions that could not be added'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of conditions added'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # Check to see if the automember rule exists
        try:
            (tdn, test_attrs) = ldap.get_entry(dn, [])
        except errors.NotFound:
            raise errors.NotFound(reason=_(u'Auto member rule: %s not found!') % keys[0])
        # Define container key
        key = options['key']
        # Check to see if the attribute is valid
        self.obj.check_attr(key)

        key = '%s=' % key
        completed = 0
        failed = {'failed': {}}

        for attr in (INCLUDE_RE, EXCLUDE_RE):
            failed['failed'][attr] = []
            if attr in options and options[attr]:
                entry_attrs[attr] = [key + condition for condition in options[attr]]
                completed += len(entry_attrs[attr])
                try:
                    (dn, old_entry) = ldap.get_entry(
                        dn, [attr], normalize=self.obj.normalize_dn)
                    for regex in old_entry:
                        if not isinstance(entry_attrs[regex], (list, tuple)):
                            entry_attrs[regex] = [entry_attrs[regex]]
                        duplicate = set(old_entry[regex]) & set(entry_attrs[regex])
                        if len(duplicate) > 0:
                            completed -= 1
                        else:
                            entry_attrs[regex] = list(entry_attrs[regex]) + old_entry[regex]
                except errors.NotFound:
                    failed['failed'][attr].append(regex)

        # Set failed and completed to they can be harvested in the execute super
        setattr(context, 'failed', failed)
        setattr(context, 'completed', completed)
        setattr(context, 'entry_attrs', entry_attrs)

        # Make sure to returned the failed results if there is nothing to remove
        if completed == 0:
            (dn, entry_attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
            raise errors.EmptyModlist
        return dn

    def execute(self, *keys, **options):
        __doc__ = _("""
        Override this so we can add completed and failed to the return result.
        """)
        try:
            result = super(automember_add_condition, self).execute(*keys, **options)
        except errors.EmptyModlist:
            result =  {'result': getattr(context, 'entry_attrs'), 'value': keys[-1]}
        result['failed'] = getattr(context, 'failed')
        result['completed'] = getattr(context, 'completed')
        result['value'] = keys[-1]
        return result

api.register(automember_add_condition)


class automember_remove_condition(LDAPUpdate):
    __doc__ = _("""
    Remove conditions from an automember rule.
    """)
    takes_options = regex_attrs + group_type
    takes_args = automember_rule
    msg_summary = _('Removed condition(s) from "%(value)s"')

    # Prepare the output to expect failed results
    has_output = (
        output.summary,
        output.Entry('result'),
        output.value,
        output.Output('failed',
            type=dict,
            doc=_('Conditions that could not be removed'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of conditions removed'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # Check to see if the automember rule exists
        try:
            (tdn, test_attrs) = ldap.get_entry(dn, [])
        except errors.NotFound:
            raise errors.NotFound(reason=_(u'Auto member rule: %s not found!') % keys[0])

        # Define container key
        type_attr_default = {'group': 'manager', 'hostgroup': 'fqdn'}
        if 'key' in options:
            key = options['key']
        else:
            key = type_attr_default[options['type']]

        key = '%s=' % key
        completed = 0
        failed = {'failed': {}}

        # Check to see if there are existing exclusive conditions present.
        (dn, exclude_present) = ldap.get_entry(
            dn, [EXCLUDE_RE], normalize=self.obj.normalize_dn)

        for attr in (INCLUDE_RE, EXCLUDE_RE):
            failed['failed'][attr] = []
            if attr in options and options[attr]:
                entry_attrs[attr] = [key + condition for condition in options[attr]]
                (dn, entry_attrs_) = ldap.get_entry(
                    dn, [attr], normalize=self.obj.normalize_dn
                )
                old_entry = entry_attrs_.get(attr, [])
                for regex in entry_attrs[attr]:
                    if regex in old_entry:
                        old_entry.remove(regex)
                        completed += 1
                    else:
                        failed['failed'][attr].append(regex)
                entry_attrs[attr] = old_entry
        # Set failed and completed to they can be harvested in the execute super
        setattr(context, 'failed', failed)
        setattr(context, 'completed', completed)
        setattr(context, 'entry_attrs', entry_attrs)

        # Make sure to returned the failed results if there is nothing to remove
        if completed == 0:
            (dn, entry_attrs) = ldap.get_entry(
                dn, attrs_list, normalize=self.obj.normalize_dn
            )
            raise errors.EmptyModlist
        return dn

    def execute(self, *keys, **options):
        __doc__ = _("""
        Override this so we can set completed and failed.
        """)
        try:
            result = super(automember_remove_condition, self).execute(*keys, **options)
        except errors.EmptyModlist:
            result =  {'result': getattr(context, 'entry_attrs'), 'value': keys[-1]}
        result['failed'] = getattr(context, 'failed')
        result['completed'] = getattr(context, 'completed')
        result['value'] = keys[-1]
        return result

api.register(automember_remove_condition)


class automember_mod(LDAPUpdate):
    __doc__ = _("""
    Modify an automember rule.
    """)
    takes_args = automember_rule
    takes_options = LDAPUpdate.takes_options + group_type
    msg_summary = _('Modified automember rule "%(value)s"')

    def execute(self, *keys, **options):
        result = super(automember_mod, self).execute(*keys, **options)
        result['value'] = keys[-1]
        return result

api.register(automember_mod)


class automember_del(LDAPDelete):
    __doc__ = _("""
    Delete an automember rule.
    """)
    takes_args = automember_rule
    takes_options = group_type
    msg_summary = _('Deleted automember rule "%(value)s"')

    def execute(self, *keys, **options):
        result = super(automember_del, self).execute(*keys, **options)
        result['value'] = keys[-1]
        return result

api.register(automember_del)


class automember_find(LDAPSearch):
    __doc__ = _("""
    Search for automember rules.
    """)
    takes_options = group_type
    has_output_params = LDAPSearch.has_output_params + automember_rule + regex_attrs

    msg_summary = ngettext(
        '%(count)d rules matched', '%(count)d rules matched', 0
    )

    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        scope = ldap.SCOPE_SUBTREE
        ndn = DN(('cn', options['type']), base_dn)
        return (filters, ndn, scope)

api.register(automember_find)


class automember_show(LDAPRetrieve):
    __doc__ = _("""
    Display information about an automember rule.
    """)
    takes_args = automember_rule
    takes_options = group_type
    has_output_params = LDAPRetrieve.has_output_params + regex_attrs

    def execute(self, *keys, **options):
        result = super(automember_show, self).execute(*keys, **options)
        result['value'] = keys[-1]
        return result

api.register(automember_show)


class automember_default_group_set(LDAPUpdate):
    __doc__ = _("""
    Set default (fallback) group for all unmatched entries.
    """)

    takes_options = (
        Str('automemberdefaultgroup',
        cli_name='default_group',
        label=_('Default (fallback) Group'),
        doc=_('Default (fallback) group for entries to land'),
        flags=['no_create', 'no_update']
        ),
    ) + group_type
    msg_summary = _('Set default (fallback) group for automember "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = DN(('cn', options['type']), api.env.container_automember)
        entry_attrs['automemberdefaultgroup'] = self.obj.dn_exists(options['type'], options['automemberdefaultgroup'])
        return dn

    def execute(self, *keys, **options):
        result = super(automember_default_group_set, self).execute(*keys, **options)
        result['value'] = options['type']
        return result

api.register(automember_default_group_set)


class automember_default_group_remove(LDAPUpdate):
    __doc__ = _("""
    Remove default (fallback) group for all unmatched entries.
    """)

    takes_options = group_type
    msg_summary = _('Removed default (fallback) group for automember "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = DN(('cn', options['type']), api.env.container_automember)
        attr = 'automemberdefaultgroup'

        (dn, entry_attrs_) = ldap.get_entry(
            dn, [attr], normalize=self.obj.normalize_dn
        )

        if attr not in entry_attrs_:
            raise errors.NotFound(reason=_(u'No default (fallback) group set'))
        else:
            entry_attrs[attr] = []
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if 'automemberdefaultgroup' not in entry_attrs:
            entry_attrs['automemberdefaultgroup'] = unicode(_('No default (fallback) group set'))
        return dn

    def execute(self, *keys, **options):
        result = super(automember_default_group_remove, self).execute(*keys, **options)
        result['value'] = options['type']
        return result

api.register(automember_default_group_remove)


class automember_default_group_show(LDAPRetrieve):
    __doc__ = _("""
    Display information about the default (fallback) automember groups.
    """)
    takes_options = group_type

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        dn = DN(('cn', options['type']), api.env.container_automember)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if 'automemberdefaultgroup' not in entry_attrs:
            entry_attrs['automemberdefaultgroup'] = unicode(_('No default (fallback) group set'))
        return dn

    def execute(self, *keys, **options):
        result = super(automember_default_group_show, self).execute(*keys, **options)
        result['value'] = options['type']
        return result

api.register(automember_default_group_show)
