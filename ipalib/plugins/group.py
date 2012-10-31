# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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

from ipalib import api
from ipalib import Int, Str
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        import ipaserver.dcerpc
        _dcerpc_bindings_installed = True
    except ImportError:
        _dcerpc_bindings_installed = False

__doc__ = _("""
Groups of users

Manage groups of users. By default, new groups are POSIX groups. You
can add the --nonposix option to the group-add command to mark a new group
as non-POSIX. You can use the --posix argument with the group-mod command
to convert a non-POSIX group into a POSIX group. POSIX groups cannot be
converted to non-POSIX groups.

Every group must have a description.

POSIX groups must have a Group ID (GID) number. Changing a GID is
supported but can have an impact on your file permissions. It is not necessary
to supply a GID when creating a group. IPA will generate one automatically
if it is not provided.

EXAMPLES:

 Add a new group:
   ipa group-add --desc='local administrators' localadmins

 Add a new non-POSIX group:
   ipa group-add --nonposix --desc='remote administrators' remoteadmins

 Convert a non-POSIX group to posix:
   ipa group-mod --posix remoteadmins

 Add a new POSIX group with a specific Group ID number:
   ipa group-add --gid=500 --desc='unix admins' unixadmins

 Add a new POSIX group and let IPA assign a Group ID number:
   ipa group-add --desc='printer admins' printeradmins

 Remove a group:
   ipa group-del unixadmins

 To add the "remoteadmins" group to the "localadmins" group:
   ipa group-add-member --groups=remoteadmins localadmins

 Add a list of users to the "localadmins" group:
   ipa group-add-member --users=test1,test2 localadmins

 Remove a user from the "localadmins" group:
   ipa group-remove-member --users=test2 localadmins

 Display information about a named group.
   ipa group-show localadmins

External group membership is designed to allow users from trusted domains
to be mapped to local POSIX groups in order to actually use IPA resources.
External members should be added to groups that specifically created as
external and non-POSIX. Such group later should be included into one of POSIX
groups.

An external group member is currently a Security Identifier (SID) as defined by
the trusted domain. When adding external group members, it is possible to
specify them in either SID, or DOM\\name, or name@domain format. IPA will attempt
to resolve passed name to SID with the use of Global Catalog of the trusted domain.

Example:

1. Create group for the trusted domain admins' mapping and their local POSIX group:

   ipa group-add --desc='<ad.domain> admins external map' ad_admins_external --external
   ipa group-add --desc='<ad.domain> admins' ad_admins

2. Add security identifier of Domain Admins of the <ad.domain> to the ad_admins_external
   group:

   ipa group-add-member ad_admins_external --external 'AD\\Domain Admins'

3. Allow members of ad_admins_external group to be associated with ad_admins POSIX group:

   ipa group-add-member ad_admins --groups ad_admins_external

4. List members of external members of ad_admins_external group to see their SIDs:

   ipa group-show ad_admins_external
""")

PROTECTED_GROUPS = (u'admins', u'trust admins', u'default smb group')

class group(LDAPObject):
    """
    Group object.
    """
    container_dn = api.env.container_group
    object_name = _('group')
    object_name_plural = _('groups')
    object_class = ['ipausergroup']
    object_class_config = 'ipagroupobjectclasses'
    possible_objectclasses = ['posixGroup', 'mepManagedEntry', 'ipaExternalGroup']
    search_attributes_config = 'ipagroupsearchfields'
    default_attributes = [
        'cn', 'description', 'gidnumber', 'member', 'memberof',
        'memberindirect', 'memberofindirect', 'ipaexternalmember',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'member': ['user', 'group'],
        'memberof': ['group', 'netgroup', 'role', 'hbacrule', 'sudorule'],
        'memberindirect': ['user', 'group'],
        'memberofindirect': ['group', 'netgroup', 'role', 'hbacrule',
        'sudorule'],
    }
    rdn_is_primary_key = True

    label = _('User Groups')
    label_singular = _('User Group')

    takes_params = (
        Str('cn',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='group_name',
            label=_('Group name'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description',
            cli_name='desc',
            label=_('Description'),
            doc=_('Group description'),
        ),
        Int('gidnumber?',
            cli_name='gid',
            label=_('GID'),
            doc=_('GID (use this option to set it manually)'),
            minvalue=1,
        ),
    )

api.register(group)

ipaexternalmember_param = Str('ipaexternalmember*',
            cli_name='external',
            label=_('External member'),
            doc=_('comma-separated list of members of a trusted domain in DOM\\name or name@domain form'),
            csv=True,
            flags=['no_create', 'no_update', 'no_search'],
        )

class group_add(LDAPCreate):
    __doc__ = _('Create a new group.')

    msg_summary = _('Added group "%(value)s"')

    takes_options = LDAPCreate.takes_options + (
        Flag('nonposix',
             cli_name='nonposix',
             doc=_('Create as a non-POSIX group'),
             default=False,
        ),
        Flag('external',
             cli_name='external',
             doc=_('Allow adding external non-IPA members from trusted domains'),
             default=False,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # As both 'external' and 'nonposix' options have default= set for
        # them, they will always be present in options dict, thus we can
        # safely reference the values
        assert isinstance(dn, DN)
        if options['external']:
            entry_attrs['objectclass'].append('ipaexternalgroup')
            if 'gidnumber' in options:
                raise errors.RequirementError(name='gid')
        elif not options['nonposix']:
            entry_attrs['objectclass'].append('posixgroup')
            if not 'gidnumber' in options:
                entry_attrs['gidnumber'] = 999
        return dn


api.register(group_add)


class group_del(LDAPDelete):
    __doc__ = _('Delete group.')

    msg_summary = _('Deleted group "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        config = ldap.get_ipa_config()[1]
        def_primary_group = config.get('ipadefaultprimarygroup', '')
        def_primary_group_dn = group_dn = self.obj.get_dn(def_primary_group)
        if dn == def_primary_group_dn:
            raise errors.DefaultGroupError()
        group_attrs = self.obj.methods.show(
            self.obj.get_primary_key_from_dn(dn), all=True
        )['result']
        if keys[0] in PROTECTED_GROUPS:
            raise errors.ProtectedEntryError(label=_(u'group'), key=keys[0],
                reason=_(u'privileged group'))
        if 'mepmanagedby' in group_attrs:
            raise errors.ManagedGroupError()
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        try:
            api.Command['pwpolicy_del'](keys[-1])
        except errors.NotFound:
            pass

        return True

api.register(group_del)


class group_mod(LDAPUpdate):
    __doc__ = _('Modify a group.')

    msg_summary = _('Modified group "%(value)s"')

    takes_options = LDAPUpdate.takes_options + (
        Flag('posix',
             cli_name='posix',
             doc=_('change to a POSIX group'),
        ),
        Flag('external',
             cli_name='external',
             doc=_('change to support external non-IPA members from trusted domains'),
             default=False,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)

        is_protected_group = keys[-1] in PROTECTED_GROUPS

        if 'rename' in options:
            if is_protected_group:
                raise errors.ProtectedEntryError(label=u'group', key=keys[-1],
                    reason=u'Cannot be renamed')

        if ('posix' in options and options['posix']) or 'gidnumber' in options:
            (dn, old_entry_attrs) = ldap.get_entry(dn, ['objectclass'])
            if 'ipaexternalgroup' in old_entry_attrs['objectclass']:
                raise errors.ExternalGroupViolation()
            if 'posixgroup' in old_entry_attrs['objectclass']:
                if options['posix']:
                    raise errors.AlreadyPosixGroup()
            else:
                old_entry_attrs['objectclass'].append('posixgroup')
                entry_attrs['objectclass'] = old_entry_attrs['objectclass']
                if not 'gidnumber' in options:
                    entry_attrs['gidnumber'] = 999

        if options['external']:
            if is_protected_group:
                raise errors.ProtectedEntryError(label=u'group', key=keys[-1],
                    reason=u'Cannot support external non-IPA members')
            (dn, old_entry_attrs) = ldap.get_entry(dn, ['objectclass'])
            if 'posixgroup' in old_entry_attrs['objectclass']:
                raise errors.PosixGroupViolation()
            if 'ipaexternalgroup' in old_entry_attrs['objectclass']:
                raise errors.AlreadyExternalGroup()
            else:
                old_entry_attrs['objectclass'].append('ipaexternalgroup')
                entry_attrs['objectclass'] = old_entry_attrs['objectclass']

        # Can't check for this in a validator because we lack context
        if 'gidnumber' in options and options['gidnumber'] is None:
            raise errors.RequirementError(name='gid')
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        # Check again for GID requirement in case someone tried to clear it
        # using --setattr.
        if call_func.func_name == 'update_entry':
            if isinstance(exc, errors.ObjectclassViolation):
                if 'gidNumber' in exc.message and 'posixGroup' in exc.message:
                    raise errors.RequirementError(name='gid')
        raise exc

api.register(group_mod)


class group_find(LDAPSearch):
    __doc__ = _('Search for groups.')

    member_attributes = ['member', 'memberof']

    msg_summary = ngettext(
        '%(count)d group matched', '%(count)d groups matched', 0
    )

    takes_options = LDAPSearch.takes_options + (
        Flag('private',
            cli_name='private',
            doc=_('search for private groups'),
        ),
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        # if looking for private groups, we need to create a new search filter,
        # because private groups have different object classes
        if options['private']:
            # filter based on options, oflt
            search_kw = self.args_options_2_entry(**options)
            search_kw['objectclass'] = ['posixGroup', 'mepManagedEntry']
            oflt = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)

            # filter based on 'criteria' argument
            search_kw = {}
            config = ldap.get_ipa_config()[1]
            attrs = config.get(self.obj.search_attributes_config, [])
            if len(attrs) == 1 and isinstance(attrs[0], basestring):
                search_attrs = attrs[0].split(',')
                for a in search_attrs:
                    search_kw[a] = args[-1]
            cflt = ldap.make_filter(search_kw, exact=False)

            filter = ldap.combine_filters((oflt, cflt), rules=ldap.MATCH_ALL)
        return (filter, base_dn, scope)

api.register(group_find)


class group_show(LDAPRetrieve):
    __doc__ = _('Display information about a named group.')
    has_output_params = LDAPRetrieve.has_output_params + (ipaexternalmember_param,)
api.register(group_show)


class group_add_member(LDAPAddMember):
    __doc__ = _('Add members to a group.')

    takes_options = (ipaexternalmember_param,)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        result = (completed, dn)
        if 'ipaexternalmember' in options:
            if not _dcerpc_bindings_installed:
                raise errors.NotFound(reason=_('Cannot perform external member validation without '
                                      'Samba 4 support installed. Make sure you have installed '
                                      'server-trust-ad sub-package of IPA on the server'))
            domain_validator = ipaserver.dcerpc.DomainValidator(self.api)
            if not domain_validator.is_configured():
                raise errors.NotFound(reason=_('Cannot perform join operation without own domain configured. '
                                      'Make sure you have run ipa-adtrust-install on the IPA server first'))
            sids = []
            failed_sids = []
            for sid in options['ipaexternalmember']:
                if domain_validator.is_trusted_sid_valid(sid):
                    sids.append(sid)
                else:
                    actual_sid = domain_validator.get_sid_trusted_domain_object(sid)
                    if isinstance(actual_sid, unicode):
                        sids.append(actual_sid)
                    else:
                        failed_sids.append((sid, 'Not a trusted domain SID'))
            if len(sids) == 0:
                raise errors.ValidationError(name=_('external member'),
                                             error=_('values are not recognized as valid SIDs from trusted domain'))
            restore = []
            if 'member' in failed and 'group' in failed['member']:
                restore = failed['member']['group']
            failed['member']['group'] = list((id,id) for id in sids)
            result = add_external_post_callback('member', 'group', 'ipaexternalmember',
                                                ldap, completed, failed, dn, entry_attrs,
                                                keys, options, external_callback_normalize=False)
            failed['member']['group'] = restore + failed_sids
        return result

api.register(group_add_member)


class group_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from a group.')

    takes_options = (ipaexternalmember_param,)

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        if keys[0] in PROTECTED_GROUPS:
            protected_group_name = keys[0]
            result = api.Command.group_show(protected_group_name)
            users_left = set(result['result'].get('member_user', []))
            users_deleted = set(options['user'])
            if users_left.issubset(users_deleted):
                raise errors.LastMemberError(key=sorted(users_deleted)[0],
                    label=_(u'group'), container=protected_group_name)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        result = (completed, dn)
        if 'ipaexternalmember' in options:
            sids = options['ipaexternalmember']
            restore = list()
            if 'member' in failed and 'group' in failed['member']:
                restore = failed['member']['group']
            failed['member']['group'] = list((id,id) for id in sids)
            result = remove_external_post_callback('member', 'group', 'ipaexternalmember',
                                                ldap, completed, failed, dn, entry_attrs,
                                                keys, options)
            failed['member']['group'] = restore
        return result

api.register(group_remove_member)


class group_detach(LDAPQuery):
    __doc__ = _('Detach a managed group from a user.')

    has_output = output.standard_value
    msg_summary = _('Detached group "%(value)s" from user "%(value)s"')

    def execute(self, *keys, **options):
        """
        This requires updating both the user and the group. We first need to
        verify that both the user and group can be updated, then we go
        about our work. We don't want a situation where only the user or
        group can be modified and we're left in a bad state.
        """
        ldap = self.obj.backend

        group_dn = self.obj.get_dn(*keys, **options)
        user_dn = self.api.Object['user'].get_dn(*keys)

        try:
            (user_dn, user_attrs) = ldap.get_entry(user_dn)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        is_managed = self.obj.has_objectclass(user_attrs['objectclass'], 'mepmanagedentry')
        if (not ldap.can_write(user_dn, "objectclass") or
            not (ldap.can_write(user_dn, "mepManagedEntry")) and is_managed):
            raise errors.ACIError(info=_('not allowed to modify user entries'))

        (group_dn, group_attrs) = ldap.get_entry(group_dn)
        is_managed = self.obj.has_objectclass(group_attrs['objectclass'], 'mepmanagedby')
        if (not ldap.can_write(group_dn, "objectclass") or
            not (ldap.can_write(group_dn, "mepManagedBy")) and is_managed):
            raise errors.ACIError(info=_('not allowed to modify group entries'))

        objectclasses = user_attrs['objectclass']
        try:
            i = objectclasses.index('mepOriginEntry')
            del objectclasses[i]
            update_attrs = {'objectclass': objectclasses, 'mepManagedEntry': None}
            ldap.update_entry(user_dn, update_attrs)
        except ValueError:
            # Somehow the user isn't managed, let it pass for now. We'll
            # let the group throw "Not managed".
            pass

        (group_dn, group_attrs) = ldap.get_entry(group_dn)
        objectclasses = group_attrs['objectclass']
        try:
            i = objectclasses.index('mepManagedEntry')
        except ValueError:
            # this should never happen
            raise errors.NotFound(reason=_('Not a managed group'))
        del objectclasses[i]

        # Make sure the resulting group has the default group objectclasses
        config = ldap.get_ipa_config()[1]
        def_objectclass = config.get(
            self.obj.object_class_config, objectclasses
        )
        objectclasses = list(set(def_objectclass + objectclasses))

        update_attrs = {'objectclass': objectclasses, 'mepManagedBy': None}
        ldap.update_entry(group_dn, update_attrs)

        return dict(
            result=True,
            value=keys[0],
        )

api.register(group_detach)
