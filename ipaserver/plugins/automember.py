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
import uuid
import time

import ldap as _ldap
import six

from ipalib import api, errors, Str, StrEnum, DNParam, Flag, _, ngettext
from ipalib import output, Method, Object
from ipalib.plugable import Registry
from .baseldap import (
    pkey_to_value,
    entry_to_dict,
    LDAPObject,
    LDAPCreate,
    LDAPUpdate,
    LDAPDelete,
    LDAPSearch,
    LDAPRetrieve)
from ipalib.request import context
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
Auto Membership Rule.
""") + _("""
Bring clarity to the membership of hosts and users by configuring inclusive
or exclusive regex patterns, you can automatically assign a new entries into
a group or hostgroup based upon attribute information.
""") + _("""
A rule is directly associated with a group by name, so you cannot create
a rule without an accompanying group or hostgroup.
""") + _("""
A condition is a regular expression used by 389-ds to match a new incoming
entry with an automember rule. If it matches an inclusive rule then the
entry is added to the appropriate group or hostgroup.
""") + _("""
A default group or hostgroup could be specified for entries that do not
match any rule. In case of user entries this group will be a fallback group
because all users are by default members of group specified in IPA config.
""") + _("""
The automember-rebuild command can be used to retroactively run automember rules
against existing entries, thus rebuilding their membership.
""") + _("""
EXAMPLES:
""") + _("""
 Add the initial group or hostgroup:
   ipa hostgroup-add --desc="Web Servers" webservers
   ipa group-add --desc="Developers" devel
""") + _("""
 Add the initial rule:
   ipa automember-add --type=hostgroup webservers
   ipa automember-add --type=group devel
""") + _("""
 Add a condition to the rule:
   ipa automember-add-condition --key=fqdn --type=hostgroup --inclusive-regex=^web[1-9]+\.example\.com webservers
   ipa automember-add-condition --key=manager --type=group --inclusive-regex=^uid=mscott devel
""") + _("""
 Add an exclusive condition to the rule to prevent auto assignment:
   ipa automember-add-condition --key=fqdn --type=hostgroup --exclusive-regex=^web5\.example\.com webservers
""") + _("""
 Add a host:
    ipa host-add web1.example.com
""") + _("""
 Add a user:
    ipa user-add --first=Tim --last=User --password tuser1 --manager=mscott
""") + _("""
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
""") + _("""
 Remove a condition from the rule:
   ipa automember-remove-condition --key=fqdn --type=hostgroup --inclusive-regex=^web[1-9]+\.example\.com webservers
""") + _("""
 Modify the automember rule:
    ipa automember-mod
""") + _("""
 Set the default (fallback) target group:
    ipa automember-default-group-set --default-group=webservers --type=hostgroup
    ipa automember-default-group-set --default-group=ipausers --type=group
""") + _("""
 Remove the default (fallback) target group:
    ipa automember-default-group-remove --type=hostgroup
    ipa automember-default-group-remove --type=group
""") + _("""
 Show the default (fallback) target group:
    ipa automember-default-group-show --type=hostgroup
    ipa automember-default-group-show --type=group
""") + _("""
 Find all of the automember rules:
    ipa automember-find
""") + _("""
 Find all of the orphan automember rules:
    ipa automember-find-orphans --type=hostgroup
 Find all of the orphan automember rules and remove them:
    ipa automember-find-orphans --type=hostgroup --remove
""") + _("""
 Display a automember rule:
    ipa automember-show --type=hostgroup webservers
    ipa automember-show --type=group devel
""") + _("""
 Delete an automember rule:
    ipa automember-del --type=hostgroup webservers
    ipa automember-del --type=group devel
""") + _("""
 Rebuild membership for all users:
    ipa automember-rebuild --type=group
""") + _("""
 Rebuild membership for all hosts:
    ipa automember-rebuild --type=hostgroup
""") + _("""
 Rebuild membership for specified users:
    ipa automember-rebuild --users=tuser1 --users=tuser2
""") + _("""
 Rebuild membership for specified hosts:
    ipa automember-rebuild --hosts=web1.example.com --hosts=web2.example.com
""")

register = Registry()

# Options used by Condition Add and Remove.
INCLUDE_RE = 'automemberinclusiveregex'
EXCLUDE_RE = 'automemberexclusiveregex'

REBUILD_TASK_CONTAINER = DN(('cn', 'automember rebuild membership'),
                            ('cn', 'tasks'),
                            ('cn', 'config'))


regex_attrs = (
    Str('automemberinclusiveregex*',
        cli_name='inclusive_regex',
        label=_('Inclusive Regex'),
        doc=_('Inclusive Regex'),
        alwaysask=True,
        flags={'no_create', 'no_update', 'no_search'},
    ),
    Str('automemberexclusiveregex*',
        cli_name='exclusive_regex',
        label=_('Exclusive Regex'),
        doc=_('Exclusive Regex'),
        alwaysask=True,
        flags={'no_create', 'no_update', 'no_search'},
    ),
)

regex_key = (
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


@register()
class automember(LDAPObject):

    """
    Bring automember to a hostgroup with an Auto Membership Rule.
    """

    container_dn = api.env.container_automember

    object_name = 'Automember rule'
    object_name_plural = 'Automember rules'
    object_class = ['top', 'automemberregexrule']
    permission_filter_objectclasses = ['automemberregexrule']
    default_attributes = [
        'automemberinclusiveregex', 'automemberexclusiveregex',
        'cn', 'automembertargetgroup', 'description', 'automemberdefaultgroup'
    ]
    managed_permissions = {
        'System: Read Automember Definitions': {
            'non_object': True,
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=automemberdefinition)'},
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'automemberscope', 'automemberfilter',
                'automembergroupingattr', 'automemberdefaultgroup',
                'automemberdisabled',
            },
            'default_privileges': {'Automember Readers',
                                   'Automember Task Administrator'},
        },
        'System: Read Automember Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'automembertargetgroup', 'description',
                'automemberexclusiveregex', 'automemberinclusiveregex',
            },
            'default_privileges': {'Automember Readers',
                                   'Automember Task Administrator'},
        },
        'System: Read Automember Tasks': {
            'non_object': True,
            'ipapermlocation': DN('cn=tasks', 'cn=config'),
            'ipapermtarget': DN('cn=*', REBUILD_TASK_CONTAINER),
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'Automember Task Administrator'},
        },
    }

    label = _('Auto Membership Rule')

    takes_params = (
        Str('cn',
            cli_name='automember_rule',
            label=_('Automember Rule'),
            doc=_('Automember Rule'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
            flags={'no_search'},
        ),
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
    ) + regex_attrs

    def dn_exists(self, otype, oname):
        ldap = self.api.Backend.ldap2
        dn = self.api.Object[otype].get_dn(oname)
        try:
            entry = ldap.get_entry(dn, [])
        except errors.NotFound:
            raise errors.NotFound(
                reason=_(u'%(otype)s "%(oname)s" not found') %
                dict(otype=otype, oname=oname)
            )
        return entry.dn

    def get_dn(self, *keys, **options):
        if self.parent_object:
            parent_dn = self.api.Object[self.parent_object].get_dn(*keys[:-1])
        else:
            parent_dn = DN(self.container_dn, api.env.basedn)
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


def automember_container_exists(ldap):
    try:
        ldap.get_entry(DN(api.env.container_automember, api.env.basedn), [])
    except errors.NotFound:
        return False
    return True


@register()
class automember_add(LDAPCreate):
    __doc__ = _("""
    Add an automember rule.
    """)
    takes_options = LDAPCreate.takes_options + group_type
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
        result['value'] = pkey_to_value(keys[-1], options)
        return result


@register()
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

    takes_options = regex_attrs + regex_key + group_type
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
            dn = ldap.get_entry(dn, []).dn
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
                    old_entry = ldap.get_entry(dn, [attr])
                    for regex in old_entry.keys():
                        if not isinstance(entry_attrs[regex], (list, tuple)):
                            entry_attrs[regex] = [entry_attrs[regex]]
                        duplicate = set(old_entry[regex]) & set(entry_attrs[regex])
                        if len(duplicate) > 0:
                            completed -= 1
                        else:
                            entry_attrs[regex] = list(entry_attrs[regex]) + old_entry[regex]
                except errors.NotFound:
                    failed['failed'][attr].append(regex)

        entry_attrs = entry_to_dict(entry_attrs, **options)

        # Set failed and completed to they can be harvested in the execute super
        setattr(context, 'failed', failed)
        setattr(context, 'completed', completed)
        setattr(context, 'entry_attrs', entry_attrs)

        # Make sure to returned the failed results if there is nothing to remove
        if completed == 0:
            ldap.get_entry(dn, attrs_list)
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
        result['value'] = pkey_to_value(keys[-1], options)
        return result


@register()
class automember_remove_condition(LDAPUpdate):
    __doc__ = _("""
    Remove conditions from an automember rule.
    """)
    takes_options = regex_attrs + regex_key + group_type
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
            ldap.get_entry(dn, [])
        except errors.NotFound:
            raise errors.NotFound(reason=_(u'Auto member rule: %s not found!') % keys[0])

        # Define container key
        type_attr_default = {'group': 'manager', 'hostgroup': 'fqdn'}
        key = options.get('key', type_attr_default[options['type']])

        key = '%s=' % key
        completed = 0
        failed = {'failed': {}}

        # Check to see if there are existing exclusive conditions present.
        dn = ldap.get_entry(dn, [EXCLUDE_RE]).dn

        for attr in (INCLUDE_RE, EXCLUDE_RE):
            failed['failed'][attr] = []
            if attr in options and options[attr]:
                entry_attrs[attr] = [key + condition for condition in options[attr]]
                entry_attrs_ = ldap.get_entry(dn, [attr])
                old_entry = entry_attrs_.get(attr, [])
                for regex in entry_attrs[attr]:
                    if regex in old_entry:
                        old_entry.remove(regex)
                        completed += 1
                    else:
                        failed['failed'][attr].append(regex)
                entry_attrs[attr] = old_entry

        entry_attrs = entry_to_dict(entry_attrs, **options)

        # Set failed and completed to they can be harvested in the execute super
        setattr(context, 'failed', failed)
        setattr(context, 'completed', completed)
        setattr(context, 'entry_attrs', entry_attrs)

        # Make sure to returned the failed results if there is nothing to remove
        if completed == 0:
            ldap.get_entry(dn, attrs_list)
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
        result['value'] = pkey_to_value(keys[-1], options)
        return result


@register()
class automember_mod(LDAPUpdate):
    __doc__ = _("""
    Modify an automember rule.
    """)
    takes_options = LDAPUpdate.takes_options + group_type
    msg_summary = _('Modified automember rule "%(value)s"')

    def execute(self, *keys, **options):
        result = super(automember_mod, self).execute(*keys, **options)
        result['value'] = pkey_to_value(keys[-1], options)
        return result


@register()
class automember_del(LDAPDelete):
    __doc__ = _("""
    Delete an automember rule.
    """)
    takes_options = group_type
    msg_summary = _('Deleted automember rule "%(value)s"')


@register()
class automember_find(LDAPSearch):
    __doc__ = _("""
    Search for automember rules.
    """)
    takes_options = group_type

    msg_summary = ngettext(
        '%(count)d rules matched', '%(count)d rules matched', 0
    )

    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        scope = ldap.SCOPE_SUBTREE
        ndn = DN(('cn', options['type']), base_dn)
        return (filters, ndn, scope)


@register()
class automember_show(LDAPRetrieve):
    __doc__ = _("""
    Display information about an automember rule.
    """)
    takes_options = group_type

    def execute(self, *keys, **options):
        result = super(automember_show, self).execute(*keys, **options)
        result['value'] = pkey_to_value(keys[-1], options)
        return result


@register()
class automember_default_group(automember):
    managed_permissions = {}

    def get_params(self):
        for param in super(automember_default_group, self).get_params():
            if param.name == 'cn':
                continue
            yield param


@register()
class automember_default_group_set(LDAPUpdate):
    __doc__ = _("""
    Set default (fallback) group for all unmatched entries.
    """)

    obj_name = 'automember_default_group'

    takes_options = (
        Str('automemberdefaultgroup',
        cli_name='default_group',
        label=_('Default (fallback) Group'),
        doc=_('Default (fallback) group for entries to land'),
        flags=['no_create', 'no_update']
        ),
    ) + group_type
    msg_summary = _('Set default (fallback) group for automember "%(value)s"')
    has_output = output.simple_entry

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = DN(('cn', options['type']), api.env.container_automember,
                api.env.basedn)
        entry_attrs['automemberdefaultgroup'] = self.obj.dn_exists(options['type'], options['automemberdefaultgroup'])
        return dn

    def execute(self, *keys, **options):
        result = super(automember_default_group_set, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['type'], options)
        return result


@register()
class automember_default_group_remove(LDAPUpdate):
    __doc__ = _("""
    Remove default (fallback) group for all unmatched entries.
    """)

    obj_name = 'automember_default_group'

    takes_options = group_type
    msg_summary = _('Removed default (fallback) group for automember "%(value)s"')
    has_output = output.simple_entry

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = DN(('cn', options['type']), api.env.container_automember,
                api.env.basedn)
        attr = 'automemberdefaultgroup'

        entry_attrs_ = ldap.get_entry(dn, [attr])

        if attr not in entry_attrs_:
            raise errors.NotFound(reason=_(u'No default (fallback) group set'))
        else:
            entry_attrs[attr] = []
        return entry_attrs_.dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if 'automemberdefaultgroup' not in entry_attrs:
            entry_attrs['automemberdefaultgroup'] = unicode(_('No default (fallback) group set'))
        return dn

    def execute(self, *keys, **options):
        result = super(automember_default_group_remove, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['type'], options)
        return result


@register()
class automember_default_group_show(LDAPRetrieve):
    __doc__ = _("""
    Display information about the default (fallback) automember groups.
    """)

    obj_name = 'automember_default_group'

    takes_options = group_type
    has_output = output.simple_entry

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        dn = DN(('cn', options['type']), api.env.container_automember,
                api.env.basedn)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if 'automemberdefaultgroup' not in entry_attrs:
            entry_attrs['automemberdefaultgroup'] = unicode(_('No default (fallback) group set'))
        return dn

    def execute(self, *keys, **options):
        result = super(automember_default_group_show, self).execute(*keys, **options)
        result['value'] = pkey_to_value(options['type'], options)
        return result


@register()
class automember_task(Object):
    takes_params = (
        DNParam(
            'dn',
            label=_('Task DN'),
            doc=_('DN of the started task'),
        ),
    )


@register()
class automember_rebuild(Method):
    __doc__ = _('Rebuild auto membership.')

    obj_name = 'automember_task'
    attr_name = 'rebuild'

    # TODO: Add a --dry-run option:
    # https://fedorahosted.org/freeipa/ticket/3936
    takes_options = (
        group_type[0].clone(
            required=False,
            label=_('Rebuild membership for all members of a grouping')
        ),
        Str(
            'users*',
            label=_('Users'),
            doc=_('Rebuild membership for specified users'),
        ),
        Str(
            'hosts*',
            label=_('Hosts'),
            doc=_('Rebuild membership for specified hosts'),
        ),
        Flag(
            'no_wait?',
            default=False,
            label=_('No wait'),
            doc=_("Don't wait for rebuilding membership"),
        ),
    )
    has_output = output.standard_entry

    def validate(self, **kw):
        """
        Validation rules:
        - at least one of 'type', 'users', 'hosts' is required
        - 'users' and 'hosts' cannot be combined together
        - if 'users' and 'type' are specified, 'type' must be 'group'
        - if 'hosts' and 'type' are specified, 'type' must be 'hostgroup'
        """
        super(automember_rebuild, self).validate(**kw)
        users, hosts, gtype = kw.get('users'), kw.get('hosts'), kw.get('type')

        if not (gtype or users or hosts):
            raise errors.MutuallyExclusiveError(
                reason=_('at least one of options: type, users, hosts must be '
                         'specified')
            )

        if users and hosts:
            raise errors.MutuallyExclusiveError(
                reason=_("users and hosts cannot both be set")
            )
        if gtype == 'group' and hosts:
            raise errors.MutuallyExclusiveError(
                reason=_("hosts cannot be set when type is 'group'")
            )
        if gtype == 'hostgroup' and users:
            raise errors.MutuallyExclusiveError(
                reason=_("users cannot be set when type is 'hostgroup'")
            )

    def execute(self, *keys, **options):
        ldap = self.api.Backend.ldap2
        cn = str(uuid.uuid4())

        gtype = options.get('type')
        if not gtype:
            gtype = 'group' if options.get('users') else 'hostgroup'

        types = {
            'group': (
                'user',
                'users',
                DN(api.env.container_user, api.env.basedn)
            ),
            'hostgroup': (
                'host',
                'hosts',
                DN(api.env.container_host, api.env.basedn)
            ),
        }

        obj_name, opt_name, basedn = types[gtype]
        obj = self.api.Object[obj_name]

        names = options.get(opt_name)
        if names:
            for name in names:
                try:
                    obj.get_dn_if_exists(name)
                except errors.NotFound:
                    raise obj.handle_not_found(name)
            search_filter = ldap.make_filter_from_attr(
                obj.primary_key.name,
                names,
                rules=ldap.MATCH_ANY
            )
        else:
            search_filter = '(%s=*)' % obj.primary_key.name

        task_dn = DN(('cn', cn), REBUILD_TASK_CONTAINER)

        entry = ldap.make_entry(
            task_dn,
            objectclass=['top', 'extensibleObject'],
            cn=[cn],
            basedn=[basedn],
            filter=[search_filter],
            scope=['sub'],
            ttl=[3600])
        ldap.add_entry(entry)

        summary = _('Automember rebuild membership task started')
        result = {'dn': task_dn}

        if not options.get('no_wait'):
            summary = _('Automember rebuild membership task completed')
            result = {}
            start_time = time.time()

            while True:
                try:
                    task = ldap.get_entry(task_dn)
                except errors.NotFound:
                    break

                if 'nstaskexitcode' in task:
                    if str(task.single_value['nstaskexitcode']) == '0':
                        summary=task.single_value['nstaskstatus']
                        break
                    else:
                        raise errors.DatabaseError(
                            desc=task.single_value['nstaskstatus'],
                            info=_("Task DN = '%s'" % task_dn))
                time.sleep(1)
                if time.time() > (start_time + 60):
                   raise errors.TaskTimeout(task=_('Automember'), task_dn=task_dn)

        return dict(
            result=result,
            summary=unicode(summary),
            value=pkey_to_value(None, options))


@register()
class automember_find_orphans(LDAPSearch):
    __doc__ = _("""
    Search for orphan automember rules. The command might need to be run as
    a privileged user user to get all orphan rules.
    """)
    takes_options = group_type + (
        Flag(
            'remove?',
            doc=_("Remove orphan automember rules"),
        ),
    )

    msg_summary = ngettext(
        '%(count)d rules matched', '%(count)d rules matched', 0
    )

    def execute(self, *keys, **options):
        results = super().execute(*keys, **options)

        remove_option = options.get('remove')
        pkey_only = options.get('pkey_only', False)
        ldap = self.obj.backend
        orphans = []
        for entry in results["result"]:
            am_dn_entry = entry['automembertargetgroup'][0]
            # Make DN for --raw option
            if not isinstance(am_dn_entry, DN):
                am_dn_entry = DN(am_dn_entry)
            try:
                ldap.get_entry(am_dn_entry)
            except errors.NotFound:
                if pkey_only:
                    # For pkey_only remove automembertargetgroup
                    del(entry['automembertargetgroup'])
                orphans.append(entry)
                if remove_option:
                    ldap.delete_entry(entry['dn'])

        results["result"][:] = orphans
        results["count"] = len(orphans)
        return results

    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args,
                     **options):
        assert isinstance(base_dn, DN)
        scope = ldap.SCOPE_SUBTREE
        ndn = DN(('cn', options['type']), base_dn)
        if options.get('pkey_only', False):
            # For pkey_only add automembertargetgroup
            attrs_list.append('automembertargetgroup')
        return filters, ndn, scope
