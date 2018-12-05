# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#   Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2014  Red Hat
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
import re

import six

from .baseldap import (LDAPQuery, LDAPObject, LDAPCreate,
                       LDAPDelete, LDAPUpdate, LDAPSearch,
                       LDAPAddAttributeViaOption,
                       LDAPRemoveAttributeViaOption,
                       LDAPRetrieve, global_output_params,
                       add_missing_object_class)
from .hostgroup import get_complete_hostgroup_member_list
from ipalib import (
    api, Str, Int, Flag, _, ngettext, errors, output
)
from ipalib.parameters import Certificate
from ipalib.constants import (
    IPA_ANCHOR_PREFIX,
    SID_ANCHOR_PREFIX,
    PATTERN_GROUPUSER_NAME,
)
from ipalib.plugable import Registry
from ipalib.util import (normalize_sshpubkey, validate_sshpubkey,
    convert_sshpubkey_post)

from ipapython.dn import DN

if six.PY3:
    unicode = str

_dcerpc_bindings_installed = False

if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc
        _dcerpc_bindings_installed = True
    except ImportError:
        pass

__doc__ = _("""
ID Views

Manage ID Views

IPA allows to override certain properties of users and groups per each host.
This functionality is primarily used to allow migration from older systems or
other Identity Management solutions.
""")

register = Registry()

protected_default_trust_view_error = errors.ProtectedEntryError(
    label=_('ID View'),
    key=u"Default Trust View",
    reason=_('system ID View')
)

fallback_to_ldap_option = Flag(
    'fallback_to_ldap?',
    default=False,
    label=_('Fallback to AD DC LDAP'),
    doc=_("Allow falling back to AD DC LDAP when resolving AD "
          "trusted objects. For two-way trusts only."),
)

DEFAULT_TRUST_VIEW_NAME = "default trust view"

ANCHOR_REGEX = re.compile(
    r':IPA:.*:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    r'|'
    r':SID:S-[0-9\-]+'
)


@register()
class idview(LDAPObject):
    """
    ID View object.
    """

    container_dn = api.env.container_views
    object_name = _('ID View')
    object_name_plural = _('ID Views')
    object_class = ['ipaIDView', 'top']
    possible_objectclasses = ['ipaNameResolutionData']
    default_attributes = ['cn', 'description', 'ipadomainresolutionorder']
    allow_rename = True

    label = _('ID Views')
    label_singular = _('ID View')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('ID View Name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
        Str('useroverrides',
            label=_('User object overrides'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('groupoverrides',
            label=_('Group object overrides'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('appliedtohosts',
            label=_('Hosts the view applies to'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'ipadomainresolutionorder?',
            cli_name='domain_resolution_order',
            label=_('Domain resolution order'),
            doc=_('colon-separated list of domains used for short name'
                  ' qualification'),
            flags={'no_search'}
        )
    )

    permission_filter_objectclasses = ['nsContainer']
    managed_permissions = {
        'System: Read ID Views': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'description', 'ipadomainresolutionorder', 'objectClass',
            },
        },
    }

    def ensure_possible_objectclasses(self, ldap, dn, entry_attrs, *keys):
        try:
            orig_entry_attrs = ldap.get_entry(dn, ['objectclass'])
        except errors.NotFound:
            raise self.handle_not_found(*keys)

        orig_objectclasses = {
            o.lower() for o in orig_entry_attrs.get('objectclass', [])}

        entry_attrs['objectclass'] = orig_entry_attrs['objectclass']

        for obj_class_name in self.possible_objectclasses:
            if obj_class_name.lower() not in orig_objectclasses:
                entry_attrs['objectclass'].append(obj_class_name)


@register()
class idview_add(LDAPCreate):
    __doc__ = _('Add a new ID View.')
    msg_summary = _('Added ID View "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.api.Object.config.validate_domain_resolution_order(entry_attrs)

        # The objectclass ipaNameResolutionData may not be present on
        # the id view. We need to add it if we define a new
        # value for ipaDomainResolutionOrder
        if 'ipadomainresolutionorder' in entry_attrs:
            add_missing_object_class(ldap, u'ipanameresolutiondata', dn,
                                     entry_attrs, update=False)
        return dn


@register()
class idview_del(LDAPDelete):
    __doc__ = _('Delete an ID View.')
    msg_summary = _('Deleted ID View "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        for key in keys:
            if key.lower() == DEFAULT_TRUST_VIEW_NAME:
                raise protected_default_trust_view_error

        return dn


@register()
class idview_mod(LDAPUpdate):
    __doc__ = _('Modify an ID View.')
    msg_summary = _('Modified an ID View "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        for key in keys:
            if key.lower() == DEFAULT_TRUST_VIEW_NAME:
                raise protected_default_trust_view_error

        self.api.Object.config.validate_domain_resolution_order(entry_attrs)
        self.obj.ensure_possible_objectclasses(ldap, dn, entry_attrs, *keys)

        return dn


@register()
class idview_find(LDAPSearch):
    __doc__ = _('Search for an ID View.')
    msg_summary = ngettext('%(count)d ID View matched',
                           '%(count)d ID Views matched', 0)


@register()
class idview_show(LDAPRetrieve):
    __doc__ = _('Display information about an ID View.')

    takes_options = LDAPRetrieve.takes_options + (
        Flag('show_hosts?',
             cli_name='show_hosts',
             doc=_('Enumerate all the hosts the view applies to.'),
        ),
    )

    has_output_params = global_output_params

    def show_id_overrides(self, dn, entry_attrs):
        ldap = self.obj.backend

        for objectclass, obj_type in [('ipaUserOverride', 'user'),
                                      ('ipaGroupOverride', 'group')]:

            # Attribute to store results is called (user|group)overrides
            attr_name = obj_type + 'overrides'

            try:
                overrides, _truncated = ldap.find_entries(
                    filter="objectclass=%s" % objectclass,
                    attrs_list=['ipaanchoruuid'],
                    base_dn=dn,
                    scope=ldap.SCOPE_ONELEVEL,
                    paged_search=True)

                resolved_overrides = []
                for override in overrides:
                    anchor = override.single_value['ipaanchoruuid']

                    try:
                        name = resolve_anchor_to_object_name(ldap, obj_type,
                                anchor)
                        resolved_overrides.append(name)

                    except (errors.NotFound, errors.ValidationError):
                        # Anchor could not be resolved, use raw
                        resolved_overrides.append(anchor)

                entry_attrs[attr_name] = resolved_overrides

            except errors.NotFound:
                # No overrides found, nothing to do
                pass

    def enumerate_hosts(self, dn, entry_attrs):
        ldap = self.obj.backend

        filter_params = {
            'ipaAssignedIDView': dn,
            'objectClass': 'ipaHost',
        }

        try:
            hosts, _truncated = ldap.find_entries(
                filter=ldap.make_filter(filter_params, rules=ldap.MATCH_ALL),
                attrs_list=['cn'],
                base_dn=api.env.container_host + api.env.basedn,
                scope=ldap.SCOPE_ONELEVEL,
                paged_search=True)

            entry_attrs['appliedtohosts'] = [host.single_value['cn']
                                             for host in hosts]
        except errors.NotFound:
            pass

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.show_id_overrides(dn, entry_attrs)

        # Enumerating hosts is a potentially expensive operation (uses paged
        # search to list all the hosts the ID view applies to). Show the list
        # of the hosts only if explicitly asked for (or asked for --all).
        # Do not display with --raw, since this attribute does not exist in
        # LDAP.

        if ((options.get('show_hosts') or options.get('all'))
            and not options.get('raw')):
            self.enumerate_hosts(dn, entry_attrs)

        return dn


class baseidview_apply(LDAPQuery):
    """
    Base class for idview_apply and idview_unapply commands.
    """

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        view = keys[-1] if keys else None
        ldap = self.obj.backend

        # Test if idview actually exists, if it does not, NotFound is raised
        if not options.get('clear_view', False):
            view_dn = self.api.Object['idview'].get_dn_if_exists(view)
            assert isinstance(view_dn, DN)

            # Check that we're not applying the Default Trust View
            if view.lower() == DEFAULT_TRUST_VIEW_NAME:
                raise errors.ValidationError(
                    name=_('ID View'),
                    error=_('Default Trust View cannot be applied on hosts')
                )

        else:
            # In case we are removing assigned view, we modify the host setting
            # the ipaAssignedIDView to None
            view_dn = None

        completed = 0
        succeeded = {'host': []}
        failed = {
            'host': [],
            'hostgroup': [],
            }

        # Make sure we ignore None passed via host or hostgroup, since it does
        # not make sense
        for key in ('host', 'hostgroup'):
            if key in options and options[key] is None:
                del options[key]

        # Generate a list of all hosts to apply the view to
        hosts_to_apply = list(options.get('host', []))

        for hostgroup in options.get('hostgroup', ()):
            try:
                hosts_to_apply += get_complete_hostgroup_member_list(hostgroup)
            except errors.NotFound:
                failed['hostgroup'].append((hostgroup, unicode(_("not found"))))
            except errors.PublicError as e:
                failed['hostgroup'].append((hostgroup, "%s : %s" % (
                                            e.__class__.__name__, str(e))))

        for host in hosts_to_apply:
            try:
                host_dn = api.Object['host'].get_dn_if_exists(host)

                host_entry = ldap.get_entry(host_dn,
                                            attrs_list=['ipaassignedidview'])
                host_entry['ipaassignedidview'] = view_dn

                ldap.update_entry(host_entry)

                # If no exception was raised, view assignment went well
                completed = completed + 1
                succeeded['host'].append(host)
            except errors.EmptyModlist:
                # If view was already applied, complain about it
                failed['host'].append((host,
                                       unicode(_("ID View already applied"))))
            except errors.NotFound:
                failed['host'].append((host, unicode(_("not found"))))
            except errors.PublicError as e:
                failed['host'].append((host, str(e)))

        # Wrap dictionary containing failures in another dictionary under key
        # 'memberhost', since that is output parameter in global_output_params
        # and thus we get nice output in the CLI
        failed = {'memberhost': failed}

        # Sort the list of affected hosts
        succeeded['host'].sort()

        # Note that we're returning the list of affected hosts even if they
        # were passed via referencing a hostgroup. This is desired, since we
        # want to stress the fact that view is applied on all the current
        # member hosts of the hostgroup and not tied with the hostgroup itself.

        return dict(
            summary=unicode(_(self.msg_summary % {'value': view})),
            succeeded=succeeded,
            completed=completed,
            failed=failed,
        )


@register()
class idview_apply(baseidview_apply):
    __doc__ = _('Applies ID View to specified hosts or current members of '
                'specified hostgroups. If any other ID View is applied to '
                'the host, it is overridden.')

    member_count_out = (_('ID View applied to %i host.'),
                        _('ID View applied to %i hosts.'))

    msg_summary = 'Applied ID View "%(value)s"'

    takes_options = (
        Str('host*',
            cli_name='hosts',
            doc=_('Hosts to apply the ID View to'),
            label=_('hosts'),
        ),
        Str('hostgroup*',
            cli_name='hostgroups',
            doc=_('Hostgroups to whose hosts apply the ID View to. Please note '
                  'that view is not applied automatically to any hosts added '
                  'to the hostgroup after running the idview-apply command.'),
            label=_('hostgroups'),
        ),
    )

    has_output = (
        output.summary,
        output.Output('succeeded',
            type=dict,
            doc=_('Hosts that this ID View was applied to.'),
        ),
        output.Output('failed',
            type=dict,
            doc=_('Hosts or hostgroups that this ID View could not be '
                  'applied to.'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of hosts the ID View was applied to:'),
        ),
    )


@register()
class idview_unapply(baseidview_apply):
    __doc__ = _('Clears ID View from specified hosts or current members of '
                'specified hostgroups.')

    member_count_out = (_('ID View cleared from %i host.'),
                        _('ID View cleared from %i hosts.'))

    msg_summary = 'Cleared ID Views'

    takes_options = (
        Str('host*',
            cli_name='hosts',
            doc=_('Hosts to clear (any) ID View from.'),
            label=_('hosts'),
        ),
        Str('hostgroup*',
            cli_name='hostgroups',
            doc=_('Hostgroups whose hosts should have ID Views cleared. Note '
                  'that view is not cleared automatically from any host added '
                  'to the hostgroup after running idview-unapply command.'),
            label=_('hostgroups'),
        ),
    )

    has_output = (
        output.summary,
        output.Output('succeeded',
            type=dict,
            doc=_('Hosts that ID View was cleared from.'),
        ),
        output.Output('failed',
            type=dict,
            doc=_('Hosts or hostgroups that ID View could not be cleared '
                  'from.'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of hosts that had a ID View was unset:'),
        ),
    )

    # Take no arguments, since ID View reference is not needed to clear
    # the hosts
    def get_args(self):
        return ()

    def execute(self, *keys, **options):
        options['clear_view'] = True
        return super(idview_unapply, self).execute(*keys, **options)


# ID overrides helper methods
def verify_trusted_domain_object_type(validator, desired_type, name_or_sid):

    object_type = validator.get_trusted_domain_object_type(name_or_sid)

    if object_type == desired_type:
        # In case SSSD returns the same type as the type being
        # searched, no problems here.
        return True

    elif desired_type == 'user' and object_type == 'both':
        # Type both denotes users with magic private groups.
        # Overriding attributes for such users is OK.
        return True

    elif desired_type == 'group' and object_type == 'both':
        # However, overriding attributes for magic private groups
        # does not make sense. One should override the GID of
        # the user itself.

        raise errors.ConversionError(
            name='identifier',
            error=_('You are trying to reference a magic private group '
                    'which is not allowed to be overridden. '
                    'Try overriding the GID attribute of the '
                    'corresponding user instead.')
            )

    return False


def resolve_object_to_anchor(ldap, obj_type, obj, fallback_to_ldap):
    """
    Resolves the user/group name to the anchor uuid:
        - first it tries to find the object as user or group in IPA (depending
          on the passed obj_type)
        - if the IPA lookup failed, lookup object SID in the trusted domains

    Takes options:
        ldap - the backend
        obj_type - either 'user' or 'group'
        obj - the name of the object, e.g. 'admin' or 'testuser'
    """

    try:
        entry = ldap.get_entry(api.Object[obj_type].get_dn(obj),
                               attrs_list=['ipaUniqueID', 'objectClass'])

        # First we check this is a valid object to override
        # - for groups, it must have ipaUserGroup objectclass
        # - for users, it must have posixAccount objectclass

        required_objectclass = {
            'user': 'posixaccount',
            'group': 'ipausergroup',
        }[obj_type]

        if not api.Object[obj_type].has_objectclass(entry['objectclass'],
                                                    required_objectclass):
            raise errors.ValidationError(
                    name=_('IPA object'),
                    error=_('system IPA objects (e.g. system groups, user '
                            'private groups) cannot be overridden')
                )

        # The domain prefix, this will need to be reworked once we
        # introduce IPA-IPA trusts
        domain = api.env.domain
        uuid = entry.single_value['ipaUniqueID']

        return "%s%s:%s" % (IPA_ANCHOR_PREFIX, domain, uuid)
    except errors.NotFound:
        pass

    # If not successful, try looking up the object in the trusted domain
    try:
        if _dcerpc_bindings_installed:
            domain_validator = ipaserver.dcerpc.DomainValidator(api)
            if domain_validator.is_configured():
                sid = domain_validator.get_trusted_domain_object_sid(obj,
                        fallback_to_ldap=fallback_to_ldap)

                # We need to verify that the object type is correct
                type_correct = verify_trusted_domain_object_type(
                        domain_validator, obj_type, sid)

                if type_correct:
                    # There is no domain prefix since SID contains information
                    # about the domain
                    return SID_ANCHOR_PREFIX + sid

    except errors.ValidationError:
        # Domain validator raises Validation Error if object name does not
        # contain domain part (either NETBIOS\ prefix or @domain.name suffix)
        pass

    # No acceptable object was found
    raise api.Object[obj_type].handle_not_found(obj)


def resolve_anchor_to_object_name(ldap, obj_type, anchor):
    """
    Resolves IPA Anchor UUID to the actual common object name (uid for users,
    cn for groups).

    Takes options:
        ldap - the backend
        anchor - the anchor, e.g.
                 ':IPA:ipa.example.com:2cb604ea-39a5-11e4-a37e-001a4a22216f'
    """

    if anchor.startswith(IPA_ANCHOR_PREFIX):

        # Prepare search parameters
        accounts_dn = DN(api.env.container_accounts, api.env.basedn)

        # Anchor of the form :IPA:<domain>:<uuid>
        # Strip the IPA prefix and the domain prefix
        uuid = anchor.rpartition(':')[-1].strip()

        # Set the object type-specific search attributes
        objectclass, name_attr = {
            'user': ('posixaccount', 'uid'),
            'group': ('ipausergroup', 'cn'),
        }[obj_type]

        entry = ldap.find_entry_by_attr(attr='ipaUniqueID',
                                        value=uuid,
                                        object_class=objectclass,
                                        attrs_list=[name_attr],
                                        base_dn=accounts_dn)

        # Return the name of the object, which is either cn for
        # groups or uid for users
        return entry.single_value[name_attr]

    elif anchor.startswith(SID_ANCHOR_PREFIX):

        # Parse the SID out from the anchor
        sid = anchor[len(SID_ANCHOR_PREFIX):].strip()

        if _dcerpc_bindings_installed:
            domain_validator = ipaserver.dcerpc.DomainValidator(api)
            if domain_validator.is_configured():
                name = domain_validator.get_trusted_domain_object_from_sid(sid)

                # We need to verify that the object type is correct
                type_correct = verify_trusted_domain_object_type(
                        domain_validator, obj_type, name)

                if type_correct:
                    return name

    # No acceptable object was found
    raise errors.NotFound(
        reason=_("Anchor '%(anchor)s' could not be resolved.")
               % dict(anchor=anchor))


def remove_ipaobject_overrides(ldap, api, dn):
    """
    Removes all ID overrides for given object. This method is to be
    consumed by -del commands of the given objects (users, groups).
    """

    entry = ldap.get_entry(dn, attrs_list=['ipaUniqueID'])
    object_uuid = entry.single_value['ipaUniqueID']

    override_filter = '(ipaanchoruuid=:IPA:{0}:{1})'.format(api.env.domain,
                                                            object_uuid)
    try:
        entries, _truncated = ldap.find_entries(
            override_filter,
            base_dn=DN(api.env.container_views, api.env.basedn),
            paged_search=True
        )
    except errors.EmptyResult:
        pass
    else:
        # In case we found something, delete it
        for entry in entries:
            ldap.delete_entry(entry)


# This is not registered on purpose, it's a base class for ID overrides
class baseidoverride(LDAPObject):
    """
    Base ID override object.
    """

    parent_object = 'idview'
    container_dn = api.env.container_views

    object_class = ['ipaOverrideAnchor', 'top']
    default_attributes = [
       'description', 'ipaAnchorUUID',
    ]

    takes_params = (
        Str('ipaanchoruuid',
            cli_name='anchor',
            primary_key=True,
            label=_('Anchor to override'),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
    )

    override_object = None

    def get_dn(self, *keys, **options):
        # If user passed raw anchor, do not try
        # to translate it.
        if ANCHOR_REGEX.match(keys[-1]):
            anchor = keys[-1]

        # Otherwise, translate object into a
        # legitimate object anchor.
        else:
            anchor = resolve_object_to_anchor(
                self.backend,
                self.override_object,
                keys[-1],
                fallback_to_ldap=options['fallback_to_ldap']
            )

        keys = keys[:-1] + (anchor, )
        return super(baseidoverride, self).get_dn(*keys, **options)

    def set_anchoruuid_from_dn(self, dn, entry_attrs):
        # TODO: Use entry_attrs.single_value once LDAPUpdate supports
        # lists in primary key fields (baseldap.LDAPUpdate.execute)
        entry_attrs['ipaanchoruuid'] = dn[0].value

    def convert_anchor_to_human_readable_form(self, entry_attrs, **options):
        if not options.get('raw'):
            anchor = entry_attrs.single_value['ipaanchoruuid']

            if anchor:
                try:
                    object_name = resolve_anchor_to_object_name(
                        self.backend,
                        self.override_object,
                        anchor
                    )
                    entry_attrs.single_value['ipaanchoruuid'] = object_name
                except errors.NotFound:
                    # If we were unable to resolve the anchor,
                    # keep it in the raw form
                    pass
                except errors.ValidationError:
                    # Same as above, ValidationError may be raised when SIDs
                    # are attempted to be converted, but the domain is no
                    # longer trusted
                    pass

    def prohibit_ipa_users_in_default_view(self, dn, entry_attrs):
        # Check if parent object is Default Trust View, if so, prohibit
        # adding overrides for IPA objects

        if dn[1].value.lower() == DEFAULT_TRUST_VIEW_NAME:
            if dn[0].value.startswith(IPA_ANCHOR_PREFIX):
                raise errors.ValidationError(
                    name=_('ID View'),
                    error=_('Default Trust View cannot contain IPA users')
                    )

    def filter_for_anchor(self, ldap, filter, options, obj_type):
        """Modify filter to support user and group names

        Allow users to pass in an IPA user/group name and resolve it to an
        anchor name.

        :param ldap: ldap connection
        :param filter: pre_callback filter
        :param options: option dict
        :param obj_type: 'user' or 'group'
        :return: modified or same filter
        """
        anchor = options.get('ipaanchoruuid', None)
        # return original filter if anchor is absent or correct
        if anchor is None or ANCHOR_REGEX.match(anchor):
            return filter
        try:
            resolved_anchor = resolve_object_to_anchor(
                ldap, obj_type, anchor,
                options.get('fallback_to_ldap', False)
            )
        except (errors.NotFound, errors.ValidationError):
            # anchor cannot be resolved, let it pass through
            return filter
        else:
            return ldap.make_filter(
                {
                    'objectClass': self.object_class,
                    'ipaanchoruuid': resolved_anchor,
                },
                rules=ldap.MATCH_ALL
            )


class baseidoverride_add(LDAPCreate):
    __doc__ = _('Add a new ID override.')
    msg_summary = _('Added ID override "%(value)s"')

    takes_options = LDAPCreate.takes_options + (fallback_to_ldap_option,)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.obj.set_anchoruuid_from_dn(dn, entry_attrs)
        self.obj.prohibit_ipa_users_in_default_view(dn, entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_anchor_to_human_readable_form(entry_attrs, **options)
        return dn


class baseidoverride_del(LDAPDelete):
    __doc__ = _('Delete an ID override.')
    msg_summary = _('Deleted ID override "%(value)s"')

    takes_options = LDAPDelete.takes_options + (fallback_to_ldap_option,)

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)

        # Make sure the entry we're deleting has all the objectclasses
        # this object requires
        try:
            entry = ldap.get_entry(dn, ['objectclass'])
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        # If not, treat it as a failed search
        for required_oc in self.obj.object_class:
            if not self.obj.has_objectclass(entry['objectclass'], required_oc):
                raise self.obj.handle_not_found(*keys)

        return dn


class baseidoverride_mod(LDAPUpdate):
    __doc__ = _('Modify an ID override.')
    msg_summary = _('Modified an ID override "%(value)s"')

    takes_options = LDAPUpdate.takes_options + (fallback_to_ldap_option,)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if 'rename' in options:
            raise errors.ValidationError(
                name=_('ID override'),
                error=_('ID overrides cannot be renamed')
                )

        self.obj.prohibit_ipa_users_in_default_view(dn, entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_anchor_to_human_readable_form(entry_attrs, **options)
        return dn


class baseidoverride_find(LDAPSearch):
    __doc__ = _('Search for an ID override.')
    msg_summary = ngettext('%(count)d ID override matched',
                           '%(count)d ID overrides matched', 0)

    takes_options = LDAPSearch.takes_options + (fallback_to_ldap_option,)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry in entries:
            self.obj.convert_anchor_to_human_readable_form(entry, **options)
        return truncated


class baseidoverride_show(LDAPRetrieve):
    __doc__ = _('Display information about an ID override.')

    takes_options = LDAPRetrieve.takes_options + (fallback_to_ldap_option,)

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_anchor_to_human_readable_form(entry_attrs, **options)
        return dn


@register()
class idoverrideuser(baseidoverride):

    object_name = _('User ID override')
    object_name_plural = _('User ID overrides')

    label = _('User ID overrides')
    label_singular = _('User ID override')
    allow_rename = True

    # ID user overrides are bindable because we map SASL GSSAPI
    # authentication of trusted users to ID user overrides in the
    # default trust view.
    bindable = True

    permission_filter_objectclasses = ['ipaUserOverride']
    managed_permissions = {
        'System: Read User ID Overrides': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectClass', 'ipaAnchorUUID', 'uidNumber', 'description',
                'homeDirectory', 'uid', 'ipaOriginalUid', 'loginShell', 'gecos',
                'gidNumber', 'ipaSshPubkey', 'usercertificate'
            },
        },
    }

    object_class = baseidoverride.object_class + ['ipaUserOverride']
    possible_objectclasses = ['ipasshuser', 'ipaSshGroupOfPubKeys']
    default_attributes = baseidoverride.default_attributes + [
       'homeDirectory', 'uidNumber', 'uid', 'ipaOriginalUid', 'loginShell',
       'ipaSshPubkey', 'gidNumber', 'gecos', 'usercertificate;binary',
    ]

    search_display_attributes = baseidoverride.default_attributes + [
       'homeDirectory', 'uidNumber', 'uid', 'ipaOriginalUid', 'loginShell',
       'ipaSshPubkey', 'gidNumber', 'gecos',
    ]

    takes_params = baseidoverride.takes_params + (
        Str('uid?',
            pattern=PATTERN_GROUPUSER_NAME,
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='login',
            label=_('User login'),
            normalizer=lambda value: value.lower(),
        ),
        Int('uidnumber?',
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number'),
            minvalue=1,
        ),
        Str('gecos?',
            label=_('GECOS'),
        ),
        Int('gidnumber?',
            label=_('GID'),
            doc=_('Group ID Number'),
            minvalue=1,
        ),
        Str('homedirectory?',
            cli_name='homedir',
            label=_('Home directory'),
        ),
        Str('loginshell?',
            cli_name='shell',
            label=_('Login shell'),
        ),
        Str('ipaoriginaluid?',
            flags=['no_option', 'no_output']
            ),
        Str('ipasshpubkey*', validate_sshpubkey,
            cli_name='sshpubkey',
            label=_('SSH public key'),
            normalizer=normalize_sshpubkey,
            flags=['no_search'],
        ),
        Certificate('usercertificate*',
              cli_name='certificate',
              label=_('Certificate'),
              doc=_('Base-64 encoded user certificate'),
              flags=['no_search',],
        ),
    )

    override_object = 'user'

    def update_original_uid_reference(self, entry_attrs):
        anchor = entry_attrs.single_value['ipaanchoruuid']
        try:
            original_uid = resolve_anchor_to_object_name(self.backend,
                                                         self.override_object,
                                                         anchor)
            entry_attrs['ipaOriginalUid'] = original_uid

        except (errors.NotFound, errors.ValidationError):
            # Anchor could not be resolved, this means we had to specify the
            # object to manipulate using a raw anchor value already, hence
            # we have no way to update the original_uid
            pass

    def convert_usercertificate_pre(self, entry_attrs):
        if 'usercertificate' in entry_attrs:
            entry_attrs['usercertificate;binary'] = entry_attrs.pop(
                'usercertificate')

    def convert_usercertificate_post(self, entry_attrs, **options):
        if 'usercertificate;binary' in entry_attrs:
            entry_attrs['usercertificate'] = entry_attrs.pop(
                'usercertificate;binary')



@register()
class idoverridegroup(baseidoverride):

    object_name = _('Group ID override')
    object_name_plural = _('Group ID overrides')

    label = _('Group ID overrides')
    label_singular = _('Group ID override')
    allow_rename = True

    permission_filter_objectclasses = ['ipaGroupOverride']
    managed_permissions = {
        'System: Read Group ID Overrides': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectClass', 'ipaAnchorUUID', 'gidNumber',
                'description', 'cn',
            },
        },
    }

    object_class = baseidoverride.object_class + ['ipaGroupOverride']
    default_attributes = baseidoverride.default_attributes + [
       'gidNumber', 'cn',
    ]

    takes_params = baseidoverride.takes_params + (
        Str('cn?',
            pattern=PATTERN_GROUPUSER_NAME,
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='group_name',
            label=_('Group name'),
            normalizer=lambda value: value.lower(),
        ),
        Int('gidnumber?',
            cli_name='gid',
            label=_('GID'),
            doc=_('Group ID Number'),
            minvalue=1,
        ),
    )

    override_object = 'group'

@register()
class idoverrideuser_add_cert(LDAPAddAttributeViaOption):
    __doc__ = _('Add one or more certificates to the idoverrideuser entry')
    msg_summary = _('Added certificates to idoverrideuser "%(value)s"')
    attribute = 'usercertificate'

    takes_options = LDAPAddAttributeViaOption.takes_options + (
        fallback_to_ldap_option,)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        dn = self.obj.get_dn(*keys, **options)
        self.obj.convert_usercertificate_pre(entry_attrs)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.convert_usercertificate_post(entry_attrs, **options)
        self.obj.convert_anchor_to_human_readable_form(entry_attrs, **options)
        return dn


@register()
class idoverrideuser_remove_cert(LDAPRemoveAttributeViaOption):
    __doc__ = _('Remove one or more certificates to the idoverrideuser entry')
    msg_summary = _('Removed certificates from idoverrideuser "%(value)s"')
    attribute = 'usercertificate'

    takes_options = LDAPRemoveAttributeViaOption.takes_options + (
        fallback_to_ldap_option,)

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        dn = self.obj.get_dn(*keys, **options)
        self.obj.convert_usercertificate_pre(entry_attrs)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj.convert_usercertificate_post(entry_attrs, **options)
        self.obj.convert_anchor_to_human_readable_form(entry_attrs, **options)

        return dn


@register()
class idoverrideuser_add(baseidoverride_add):
    __doc__ = _('Add a new User ID override.')
    msg_summary = _('Added User ID override "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = super(idoverrideuser_add, self).pre_callback(ldap, dn,
                 entry_attrs, attrs_list, *keys, **options)

        entry_attrs['objectclass'].append('ipasshuser')
        self.obj.convert_usercertificate_pre(entry_attrs)

        # Update the ipaOriginalUid
        self.obj.update_original_uid_reference(entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        dn = super(idoverrideuser_add, self).post_callback(ldap, dn,
                 entry_attrs, *keys, **options)
        convert_sshpubkey_post(entry_attrs)
        self.obj.convert_usercertificate_post(entry_attrs, **options)
        return dn



@register()
class idoverrideuser_del(baseidoverride_del):
    __doc__ = _('Delete an User ID override.')
    msg_summary = _('Deleted User ID override "%(value)s"')


@register()
class idoverrideuser_mod(baseidoverride_mod):
    __doc__ = _('Modify an User ID override.')
    msg_summary = _('Modified an User ID override "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = super(idoverrideuser_mod, self).pre_callback(ldap, dn,
                 entry_attrs, attrs_list, *keys, **options)

        # Update the ipaOriginalUid
        self.obj.set_anchoruuid_from_dn(dn, entry_attrs)
        self.obj.update_original_uid_reference(entry_attrs)
        if 'objectclass' in entry_attrs:
            obj_classes = entry_attrs['objectclass']
        else:
            _entry_attrs = ldap.get_entry(dn, ['objectclass'])
            obj_classes = entry_attrs['objectclass'] = _entry_attrs['objectclass']

        if 'ipasshpubkey' in entry_attrs and 'ipasshuser' not in obj_classes:
            obj_classes.append('ipasshuser')

        self.obj.convert_usercertificate_pre(entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        dn = super(idoverrideuser_mod, self).post_callback(ldap, dn,
                 entry_attrs, *keys, **options)
        convert_sshpubkey_post(entry_attrs)
        self.obj.convert_usercertificate_post(entry_attrs, **options)
        return dn


@register()
class idoverrideuser_find(baseidoverride_find):
    __doc__ = _('Search for an User ID override.')
    msg_summary = ngettext('%(count)d User ID override matched',
                           '%(count)d User ID overrides matched', 0)

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args,
                     **options):
        result = super(idoverrideuser_find, self).pre_callback(
            ldap, filter, attrs_list, base_dn, scope, *args, **options
        )
        filter, base_dn, scope = result
        filter = self.obj.filter_for_anchor(ldap, filter, options, 'user')
        return filter, base_dn, scope

    def post_callback(self, ldap, entries, truncated, *args, **options):
        truncated = super(idoverrideuser_find, self).post_callback(
            ldap, entries, truncated, *args, **options)
        for entry in entries:
            convert_sshpubkey_post(entry)
            self.obj.convert_usercertificate_post(entry, **options)
        return truncated


@register()
class idoverrideuser_show(baseidoverride_show):
    __doc__ = _('Display information about an User ID override.')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        dn = super(idoverrideuser_show, self).post_callback(ldap, dn,
                 entry_attrs, *keys, **options)
        convert_sshpubkey_post(entry_attrs)
        self.obj.convert_usercertificate_post(entry_attrs, **options)
        return dn


@register()
class idoverridegroup_add(baseidoverride_add):
    __doc__ = _('Add a new Group ID override.')
    msg_summary = _('Added Group ID override "%(value)s"')


@register()
class idoverridegroup_del(baseidoverride_del):
    __doc__ = _('Delete an Group ID override.')
    msg_summary = _('Deleted Group ID override "%(value)s"')


@register()
class idoverridegroup_mod(baseidoverride_mod):
    __doc__ = _('Modify an Group ID override.')
    msg_summary = _('Modified an Group ID override "%(value)s"')


@register()
class idoverridegroup_find(baseidoverride_find):
    __doc__ = _('Search for an Group ID override.')
    msg_summary = ngettext('%(count)d Group ID override matched',
                           '%(count)d Group ID overrides matched', 0)

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args,
                     **options):
        result = super(idoverridegroup_find, self).pre_callback(
            ldap, filter, attrs_list, base_dn, scope, *args, **options
        )
        filter, base_dn, scope = result
        filter = self.obj.filter_for_anchor(ldap, filter, options, 'group')
        return filter, base_dn, scope


@register()
class idoverridegroup_show(baseidoverride_show):
    __doc__ = _('Display information about an Group ID override.')
