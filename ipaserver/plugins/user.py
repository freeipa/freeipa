# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

from __future__ import absolute_import

import logging
import time
from time import gmtime, strftime
import posixpath

import six

from ipalib import api
from ipalib import errors
from ipalib import Bool, Flag, Str
from .baseuser import (
    baseuser,
    baseuser_add,
    baseuser_del,
    baseuser_mod,
    baseuser_find,
    baseuser_show,
    NO_UPG_MAGIC,
    UPG_DEFINITION_DN,
    baseuser_output_params,
    validate_nsaccountlock,
    convert_nsaccountlock,
    fix_addressbook_permission_bindrule,
    baseuser_add_manager,
    baseuser_remove_manager,
    baseuser_add_cert,
    baseuser_remove_cert,
    baseuser_add_principal,
    baseuser_remove_principal,
    baseuser_add_certmapdata,
    baseuser_remove_certmapdata)
from .idviews import remove_ipaobject_overrides
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject,
    pkey_to_value,
    LDAPCreate,
    LDAPSearch,
    LDAPQuery,
    LDAPMultiQuery)
from . import baseldap
from ipalib.request import context
from ipalib import _, ngettext
from ipalib import output
from ipaplatform.paths import paths
from ipaplatform.constants import constants as platformconstants
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient
from ipapython.ipautil import ipa_generate_password, TMP_PWD_ENTROPY_BITS
from ipalib.capabilities import client_has_capability
from ipaserver.masters import get_masters

if six.PY3:
    unicode = str

__doc__ = _("""
Users

Manage user entries. All users are POSIX users.

IPA supports a wide range of username formats, but you need to be aware of any
restrictions that may apply to your particular environment. For example,
usernames that start with a digit or usernames that exceed a certain length
may cause problems for some UNIX systems.
Use 'ipa config-mod' to change the username format allowed by IPA tools.

Disabling a user account prevents that user from obtaining new Kerberos
credentials. It does not invalidate any credentials that have already
been issued.

Password management is not a part of this module. For more information
about this topic please see: ipa help passwd

Account lockout on password failure happens per IPA master. The user-status
command can be used to identify which master the user is locked out on.
It is on that master the administrator must unlock the user.

EXAMPLES:

 Add a new user:
   ipa user-add --first=Tim --last=User --password tuser1

 Find all users whose entries include the string "Tim":
   ipa user-find Tim

 Find all users with "Tim" as the first name:
   ipa user-find --first=Tim

 Disable a user account:
   ipa user-disable tuser1

 Enable a user account:
   ipa user-enable tuser1

 Delete a user:
   ipa user-del tuser1
""")

logger = logging.getLogger(__name__)

register = Registry()


user_output_params = baseuser_output_params


def check_protected_member(user, protected_group_name=u'admins'):
    '''
    Ensure the last enabled member of a protected group cannot be deleted or
    disabled by raising LastMemberError.
    '''

    # Get all users in the protected group
    result = api.Command.user_find(in_group=protected_group_name)

    # Build list of users in the protected group who are enabled
    result = result['result']
    enabled_users = [entry['uid'][0] for entry in result if not entry['nsaccountlock']]

    # If the user is the last enabled user raise LastMemberError exception
    if enabled_users == [user]:
        raise errors.LastMemberError(key=user, label=_(u'group'),
            container=protected_group_name)

@register()
class user(baseuser):
    """
    User object.
    """

    container_dn              = baseuser.active_container_dn
    label                     = _('Users')
    label_singular            = _('User')
    object_name               = _('user')
    object_name_plural        = _('users')
    managed_permissions = {
        'System: Read User Standard Attributes': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'anonymous',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'sn', 'description', 'title', 'uid',
                'displayname', 'givenname', 'initials', 'manager', 'gecos',
                'gidnumber', 'homedirectory', 'loginshell', 'uidnumber',
                'ipantsecurityidentifier'
            },
        },
        'System: Read User Addressbook Attributes': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'seealso', 'telephonenumber',
                'facsimiletelephonenumber', 'l', 'ou', 'st', 'postalcode', 'street',
                'destinationindicator', 'internationalisdnnumber',
                'physicaldeliveryofficename', 'postaladdress', 'postofficebox',
                'preferreddeliverymethod', 'registeredaddress',
                'teletexterminalidentifier', 'telexnumber', 'x121address',
                'carlicense', 'departmentnumber', 'employeenumber',
                'employeetype', 'preferredlanguage', 'mail', 'mobile', 'pager',
                'audio', 'businesscategory', 'homephone', 'homepostaladdress',
                'jpegphoto', 'labeleduri', 'o', 'photo', 'roomnumber',
                'secretary', 'usercertificate',
                'usersmimecertificate', 'x500uniqueidentifier',
                'inetuserhttpurl', 'inetuserstatus',
                'ipacertmapdata',
            },
            'fixup_function': fix_addressbook_permission_bindrule,
        },
        'System: Read User IPA Attributes': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'ipauniqueid', 'ipasshpubkey', 'ipauserauthtype', 'userclass',
            },
            'fixup_function': fix_addressbook_permission_bindrule,
        },
        'System: Read User Kerberos Attributes': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'krbprincipalname', 'krbcanonicalname', 'krbprincipalaliases',
                'krbprincipalexpiration', 'krbpasswordexpiration',
                'krblastpwdchange', 'nsaccountlock', 'krbprincipaltype',
            },
        },
        'System: Read User Kerberos Login Attributes': {
            'replaces_global_anonymous_aci': True,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'krblastsuccessfulauth', 'krblastfailedauth',
                'krblastpwdchange', 'krblastadminunlock',
                'krbloginfailedcount', 'krbpwdpolicyreference',
                'krbticketpolicyreference', 'krbupenabled',
            },
            'default_privileges': {'User Administrators'},
        },
        'System: Read User Membership': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'memberof',
            },
        },
        'System: Read UPG Definition': {
            # Required for adding users
            'replaces_global_anonymous_aci': True,
            'non_object': True,
            'ipapermlocation': UPG_DEFINITION_DN,
            'ipapermtarget': UPG_DEFINITION_DN,
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'User Administrators'},
        },
        'System: Add Users': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Add Users";allow (add) groupdn = "ldap:///cn=Add Users,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'User Administrators'},
        },
        'System: Add User to default group': {
            'non_object': True,
            'ipapermright': {'write'},
            'ipapermlocation': DN(api.env.container_group, api.env.basedn),
            'ipapermtarget': DN('cn=ipausers', api.env.container_group,
                                api.env.basedn),
            'ipapermdefaultattr': {'member'},
            'replaces': [
                '(targetattr = "member")(target = "ldap:///cn=ipausers,cn=groups,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Add user to default group";allow (write) groupdn = "ldap:///cn=Add user to default group,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'User Administrators'},
        },
        'System: Change User password': {
            'ipapermright': {'write'},
            'ipapermtargetfilter': [
                '(objectclass=posixaccount)',
                '(!(memberOf=%s))' % DN('cn=admins',
                                        api.env.container_group,
                                        api.env.basedn),
            ],
            'ipapermdefaultattr': {
                'krbprincipalkey', 'passwordhistory', 'sambalmpassword',
                'sambantpassword', 'userpassword', 'krbpasswordexpiration'
            },
            'replaces': [
                '(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(targetattr = "userpassword || krbprincipalkey || sambalmpassword || sambantpassword || passwordhistory")(version 3.0;acl "permission:Change a user password";allow (write) groupdn = "ldap:///cn=Change a user password,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetfilter = "(!(memberOf=cn=admins,cn=groups,cn=accounts,$SUFFIX))")(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(targetattr = "userpassword || krbprincipalkey || sambalmpassword || sambantpassword || passwordhistory")(version 3.0;acl "permission:Change a user password";allow (write) groupdn = "ldap:///cn=Change a user password,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetattr = "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory")(version 3.0; acl "Windows PassSync service can write passwords"; allow (write) userdn="ldap:///uid=passsync,cn=sysaccounts,cn=etc,$SUFFIX";)',
            ],
            'default_privileges': {
                'User Administrators',
                'Modify Users and Reset passwords',
                'PassSync Service',
            },
        },
        'System: Manage User SSH Public Keys': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'ipasshpubkey'},
            'replaces': [
                '(targetattr = "ipasshpubkey")(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Manage User SSH Public Keys";allow (write) groupdn = "ldap:///cn=Manage User SSH Public Keys,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'User Administrators'},
        },
        'System: Manage User Certificates': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'usercertificate'},
            'default_privileges': {
                'User Administrators',
                'Modify Users and Reset passwords',
            },
        },
        'System: Manage User Principals': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'krbprincipalname', 'krbcanonicalname'},
            'default_privileges': {
                'User Administrators',
                'Modify Users and Reset passwords',
            },
        },
        'System: Modify Users': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'businesscategory', 'carlicense', 'cn', 'departmentnumber',
                'description', 'displayname', 'employeetype',
                'employeenumber', 'facsimiletelephonenumber',
                'gecos', 'givenname', 'homedirectory', 'homephone',
                'inetuserhttpurl', 'initials', 'l', 'labeleduri', 'loginshell',
                'manager', 'mail', 'mepmanagedentry', 'mobile', 'objectclass',
                'ou', 'pager', 'postalcode', 'roomnumber', 'secretary',
                'seealso', 'sn', 'st', 'street', 'telephonenumber', 'title',
                'userclass', 'preferredlanguage'
            },
            'replaces': [
                '(targetattr = "givenname || sn || cn || displayname || title || initials || loginshell || gecos || homephone || mobile || pager || facsimiletelephonenumber || telephonenumber || street || roomnumber || l || st || postalcode || manager || secretary || description || carlicense || labeleduri || inetuserhttpurl || seealso || employeetype || businesscategory || ou || mepmanagedentry || objectclass")(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Modify Users";allow (write) groupdn = "ldap:///cn=Modify Users,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {
                'User Administrators',
                'Modify Users and Reset passwords',
            },
        },
        'System: Remove Users': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Remove Users";allow (delete) groupdn = "ldap:///cn=Remove Users,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'User Administrators'},
        },
        'System: Unlock User': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'krblastadminunlock', 'krbloginfailedcount', 'nsaccountlock',
            },
            'replaces': [
                '(targetattr = "krbLastAdminUnlock || krbLoginFailedCount")(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(version 3.0;acl "permission:Unlock user accounts";allow (write) groupdn = "ldap:///cn=Unlock user accounts,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'User Administrators'},
        },
        'System: Read User Compat Tree': {
            'non_object': True,
            'ipapermbindruletype': 'anonymous',
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=users', 'cn=compat', api.env.basedn),
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'uid', 'cn', 'gecos', 'gidnumber', 'uidnumber',
                'homedirectory', 'loginshell',
            },
        },
        'System: Read User Views Compat Tree': {
            'non_object': True,
            'ipapermbindruletype': 'anonymous',
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN('cn=users', 'cn=*', 'cn=views', 'cn=compat', api.env.basedn),
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'uid', 'cn', 'gecos', 'gidnumber', 'uidnumber',
                'homedirectory', 'loginshell',
            },
        },
        'System: Read User NT Attributes': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'ntuserdomainid', 'ntuniqueid', 'ntuseracctexpires',
                'ntusercodepage', 'ntuserdeleteaccount', 'ntuserlastlogoff',
                'ntuserlastlogon',
            },
            'default_privileges': {'PassSync Service'},
        },
        'System: Manage User Certificate Mappings': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'ipacertmapdata', 'objectclass'},
            'default_privileges': {
                'Certificate Identity Mapping Administrators'
            },
        },
    }

    takes_params = baseuser.takes_params + (
        Bool('nsaccountlock?',
            cli_name=('disabled'),
            default=False,
            label=_('Account disabled'),
        ),
        Bool('preserved?',
            label=_('Preserved user'),
            default=False,
            flags=['virtual_attribute', 'no_create', 'no_update'],
        ),
    )

    def get_delete_dn(self, *keys, **options):
        active_dn = self.get_dn(*keys, **options)
        return DN(active_dn[0], self.delete_container_dn, api.env.basedn)

    def get_either_dn(self, *keys, **options):
        '''
        Returns the DN of a user
        The user can be active (active container) or delete (delete container)
        If the user does not exist, returns the Active user DN
        '''
        ldap = self.backend
        # Check that this value is a Active user
        try:
            active_dn = self.get_dn(*keys, **options)
            ldap.get_entry(active_dn, ['dn'])

            # The Active user exists
            dn = active_dn
        except errors.NotFound:
            # Check that this value is a Delete user
            delete_dn = self.get_delete_dn(*keys, **options)
            try:
                ldap.get_entry(delete_dn, ['dn'])

                # The Delete user exists
                dn = delete_dn
            except errors.NotFound:
                # The user is neither Active/Delete -> returns that Active DN
                dn = active_dn

        return dn

    def _normalize_manager(self, manager):
        """
        Given a userid verify the user's existence and return the dn.
        """
        return super(user, self).normalize_manager(manager, self.active_container_dn)

    def get_preserved_attribute(self, entry, options):
        if options.get('raw', False):
            return
        delete_container_dn = DN(self.delete_container_dn, api.env.basedn)
        if entry.dn.endswith(delete_container_dn):
            entry['preserved'] = True
        elif options.get('all', False):
            entry['preserved'] = False


@register()
class user_add(baseuser_add):
    __doc__ = _('Add a new user.')

    msg_summary = _('Added user "%(value)s"')

    has_output_params = baseuser_add.has_output_params + user_output_params

    takes_options = LDAPCreate.takes_options + (
        Flag('noprivate',
            cli_name='noprivate',
            doc=_('Don\'t create user private group'),
        ),
    )

    def get_options(self):
        for option in super(user_add, self).get_options():
            if option.name == "nsaccountlock":
                flags = set(option.flags)
                flags.add("no_option")
                option = option.clone(flags=flags)
            yield option

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        delete_dn = self.obj.get_delete_dn(*keys, **options)
        try:
            ldap.get_entry(delete_dn, [''])
        except errors.NotFound:
            pass
        else:
            raise self.obj.handle_duplicate_entry(*keys)

        if not options.get('noprivate', False) and ldap.has_upg():
            try:
                # The Managed Entries plugin will allow a user to be created
                # even if a group has a duplicate name. This would leave a user
                # without a private group. Check for both the group and the user.
                self.api.Object['group'].get_dn_if_exists(keys[-1])
                try:
                    self.api.Command['user_show'](keys[-1])
                    self.obj.handle_duplicate_entry(*keys)
                except errors.NotFound:
                    raise errors.ManagedGroupExistsError(group=keys[-1])
            except errors.NotFound:
                pass
        else:
            # we don't want an user private group to be created for this user
            # add NO_UPG_MAGIC description attribute to let the DS plugin know
            entry_attrs.setdefault('description', [])
            entry_attrs['description'].append(NO_UPG_MAGIC)

        entry_attrs.setdefault('uidnumber', baseldap.DNA_MAGIC)

        if not client_has_capability(
                options['version'], 'optional_uid_params'):
            # https://fedorahosted.org/freeipa/ticket/2886
            # Old clients say 999 (OLD_DNA_MAGIC) when they really mean
            # "assign a value dynamically".
            OLD_DNA_MAGIC = 999
            if entry_attrs.get('uidnumber') == OLD_DNA_MAGIC:
                entry_attrs['uidnumber'] = baseldap.DNA_MAGIC
            if entry_attrs.get('gidnumber') == OLD_DNA_MAGIC:
                entry_attrs['gidnumber'] = baseldap.DNA_MAGIC

        validate_nsaccountlock(entry_attrs)
        config = ldap.get_ipa_config()
        if 'ipamaxusernamelength' in config:
            if len(keys[-1]) > int(config.get('ipamaxusernamelength')[0]):
                raise errors.ValidationError(
                    name=self.obj.primary_key.cli_name,
                    error=_('can be at most %(len)d characters') % dict(
                        len = int(config.get('ipamaxusernamelength')[0])
                    )
                )
        default_shell = config.get('ipadefaultloginshell',
                                   [platformconstants.DEFAULT_SHELL])[0]
        entry_attrs.setdefault('loginshell', default_shell)
        # hack so we can request separate first and last name in CLI
        full_name = '%s %s' % (entry_attrs['givenname'], entry_attrs['sn'])
        entry_attrs.setdefault('cn', full_name)
        if 'homedirectory' not in entry_attrs:
            # get home's root directory from config
            homes_root = config.get('ipahomesrootdir', [paths.HOME_DIR])[0]
            # build user's home directory based on his uid
            entry_attrs['homedirectory'] = posixpath.join(homes_root, keys[-1])
        entry_attrs.setdefault('krbprincipalname', '%s@%s' % (entry_attrs['uid'], api.env.realm))

        if entry_attrs.get('gidnumber') is None:
            # gidNumber wasn't specified explicity, find out what it should be
            if not options.get('noprivate', False) and ldap.has_upg():
                # User Private Groups - uidNumber == gidNumber
                entry_attrs['gidnumber'] = entry_attrs['uidnumber']
            else:
                # we're adding new users to a default group, get its gidNumber
                # get default group name from config
                def_primary_group = config.get('ipadefaultprimarygroup')
                group_dn = self.api.Object['group'].get_dn(def_primary_group)
                try:
                    group_attrs = ldap.get_entry(group_dn, ['gidnumber'])
                except errors.NotFound:
                    error_msg = _('Default group for new users not found')
                    raise errors.NotFound(reason=error_msg)
                if 'gidnumber' not in group_attrs:
                    error_msg = _('Default group for new users is not POSIX')
                    raise errors.NotFound(reason=error_msg)
                entry_attrs['gidnumber'] = group_attrs['gidnumber']

        if 'userpassword' not in entry_attrs and options.get('random'):
            entry_attrs['userpassword'] = ipa_generate_password(
                entropy_bits=TMP_PWD_ENTROPY_BITS)
            # save the password so it can be displayed in post_callback
            setattr(context, 'randompassword', entry_attrs['userpassword'])

        if 'mail' in entry_attrs:
            entry_attrs['mail'] = self.obj.normalize_and_validate_email(entry_attrs['mail'], config)
        else:
            # No e-mail passed in. If we have a default e-mail domain set
            # then we'll add it automatically.
            defaultdomain = config.get('ipadefaultemaildomain', [None])[0]
            if defaultdomain:
                entry_attrs['mail'] = self.obj.normalize_and_validate_email(keys[-1], config)

        if 'manager' in entry_attrs:
            entry_attrs['manager'] = self.obj.normalize_manager(entry_attrs['manager'], self.obj.active_container_dn)

        if 'userclass' in entry_attrs and \
           'ipauser' not in entry_attrs['objectclass']:
            entry_attrs['objectclass'].append('ipauser')

        if 'ipauserauthtype' in entry_attrs and \
           'ipauserauthtypeclass' not in entry_attrs['objectclass']:
            entry_attrs['objectclass'].append('ipauserauthtypeclass')

        rcl = entry_attrs.get('ipatokenradiusconfiglink', None)
        if rcl:
            if 'ipatokenradiusproxyuser' not in entry_attrs['objectclass']:
                entry_attrs['objectclass'].append('ipatokenradiusproxyuser')

            answer = self.api.Object['radiusproxy'].get_dn_if_exists(rcl)
            entry_attrs['ipatokenradiusconfiglink'] = answer

        self.pre_common_callback(ldap, dn, entry_attrs, attrs_list, *keys,
                                 **options)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        config = ldap.get_ipa_config()
        # add the user we just created into the default primary group
        def_primary_group = config.get('ipadefaultprimarygroup')
        group_dn = self.api.Object['group'].get_dn(def_primary_group)

        # if the user is already a member of default primary group,
        # do not raise error
        # this can happen if automember rule or default group is set
        try:
            ldap.add_entry_to_group(dn, group_dn)
        except errors.AlreadyGroupMember:
            pass

        # Fetch the entry again to update memberof, mep data, etc updated
        # at the end of the transaction.
        newentry = ldap.get_entry(dn, ['*'])

        # delete description attribute NO_UPG_MAGIC if present
        if (options.get('noprivate', False) or not ldap.has_upg()) and \
                'description' in newentry and \
                NO_UPG_MAGIC in newentry['description']:
            newentry['description'].remove(NO_UPG_MAGIC)
            ldap.update_entry(newentry)

        entry_attrs.update(newentry)

        if options.get('random', False):
            try:
                entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
            except AttributeError:
                # if both randompassword and userpassword options were used
                pass

        self.obj.get_preserved_attribute(entry_attrs, options)

        self.post_common_callback(ldap, dn, entry_attrs, *keys, **options)

        return dn


@register()
class user_del(baseuser_del):
    __doc__ = _('Delete a user.')

    msg_summary = _('Deleted user "%(value)s"')

    takes_options = baseuser_del.takes_options + (
        Bool('preserve?',
            exclude='cli',
        ),
    )

    def _preserve_user(self, pkey, delete_container, **options):
        assert isinstance(delete_container, DN)

        dn = self.obj.get_either_dn(pkey, **options)
        delete_dn = DN(dn[0], delete_container)
        ldap = self.obj.backend
        logger.debug("preserve move %s -> %s", dn, delete_dn)

        if dn.endswith(delete_container):
            raise errors.ExecutionError(
                _('%s: user is already preserved' % pkey)
            )
        # Check that this value is a Active user
        try:
            original_entry_attrs = self._exc_wrapper(
                pkey, options, ldap.get_entry)(dn, ['dn'])
        except errors.NotFound:
            raise self.obj.handle_not_found(pkey)

        for callback in self.get_callbacks('pre'):
            dn = callback(self, ldap, dn, pkey, **options)
            assert isinstance(dn, DN)

        # start to move the entry to Delete container
        self._exc_wrapper(pkey, options, ldap.move_entry)(dn, delete_dn,
                                                          del_old=True)

        # Then clear the credential attributes
        attrs_to_clear = ['krbPrincipalKey', 'krbLastPwdChange',
                          'krbPasswordExpiration', 'userPassword']

        entry_attrs = self._exc_wrapper(pkey, options, ldap.get_entry)(
            delete_dn, attrs_to_clear)

        clearedCredential = False
        for attr in attrs_to_clear:
            if attr.lower() in entry_attrs:
                del entry_attrs[attr]
                clearedCredential = True
        if clearedCredential:
            self._exc_wrapper(pkey, options, ldap.update_entry)(entry_attrs)

        # Then restore some original entry attributes
        attrs_to_restore = ['secretary', 'managedby', 'manager', 'ipauniqueid',
                            'uidnumber', 'gidnumber', 'passwordHistory']

        entry_attrs = self._exc_wrapper(
            pkey, options, ldap.get_entry)(delete_dn, attrs_to_restore)

        restoreAttr = False
        for attr in attrs_to_restore:
            if ((attr.lower() in original_entry_attrs) and
                    not (attr.lower() in entry_attrs)):
                restoreAttr = True
                entry_attrs[attr.lower()] = original_entry_attrs[attr.lower()]
        if restoreAttr:
            self._exc_wrapper(pkey, options, ldap.update_entry)(entry_attrs)

    def pre_callback(self, ldap, dn, *keys, **options):
        dn = self.obj.get_either_dn(*keys, **options)

        # For User life Cycle: user-del is a common plugin
        # command to delete active user (active container) and
        # delete user (delete container).
        # If the target entry is a Delete entry, skip the orphaning/removal
        # of OTP tokens.
        check_protected_member(keys[-1])

        if not options.get('preserve', False):
            # Remove any ID overrides tied with this user
            try:
                remove_ipaobject_overrides(self.obj.backend, self.obj.api, dn)
            except errors.NotFound:
                raise self.obj.handle_not_found(*keys)

        if dn.endswith(DN(self.obj.delete_container_dn, api.env.basedn)):
            return dn

        # Delete all tokens owned and managed by this user.
        # Orphan all tokens owned but not managed by this user.
        owner = self.api.Object.user.get_primary_key_from_dn(dn)
        results = self.api.Command.otptoken_find(
            ipatokenowner=owner, no_members=False)['result']
        for token in results:
            orphan = not [x for x in token.get('managedby_user', []) if x == owner]
            token = self.api.Object.otptoken.get_primary_key_from_dn(token['dn'])
            if orphan:
                self.api.Command.otptoken_mod(token, ipatokenowner=None)
            else:
                self.api.Command.otptoken_del(token)

        return dn

    def execute(self, *keys, **options):

        # We are going to permanent delete or the user is already in the delete container.
        delete_container = DN(self.obj.delete_container_dn, self.api.env.basedn)

        # The user to delete is active and there is no 'no_preserve' option
        if options.get('preserve', False):
            failed = []
            preserved = []
            for pkey in keys[-1]:
                try:
                    self._preserve_user(pkey, delete_container, **options)
                    preserved.append(pkey_to_value(pkey, options))
                except Exception:
                    if not options.get('continue', False):
                        raise
                    failed.append(pkey_to_value(pkey, options))

            val = dict(result=dict(failed=failed), value=preserved)
            return val
        else:
            return super(user_del, self).execute(*keys, **options)


@register()
class user_mod(baseuser_mod):
    __doc__ = _('Modify a user.')

    msg_summary = _('Modified user "%(value)s"')

    has_output_params = baseuser_mod.has_output_params + user_output_params

    def get_options(self):
        for option in super(user_mod, self).get_options():
            if option.name == "nsaccountlock":
                flags = set(option.flags)
                flags.add("no_option")
                option = option.clone(flags=flags)
            yield option

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = self.obj.get_either_dn(*keys, **options)
        self.pre_common_callback(ldap, dn, entry_attrs, attrs_list, *keys,
                                 **options)
        validate_nsaccountlock(entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.post_common_callback(ldap, dn, entry_attrs, *keys, **options)
        self.obj.get_preserved_attribute(entry_attrs, options)
        return dn


@register()
class user_find(baseuser_find):
    __doc__ = _('Search for users.')

    member_attributes = ['memberof']
    has_output_params = baseuser_find.has_output_params + user_output_params

    msg_summary = ngettext(
        '%(count)d user matched', '%(count)d users matched', 0
    )

    takes_options = LDAPSearch.takes_options + (
        Flag('whoami',
            label=_('Self'),
            doc=_('Display user record for current Kerberos principal'),
        ),
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *keys, **options):
        assert isinstance(base_dn, DN)
        self.pre_common_callback(ldap, filter, attrs_list, base_dn, scope,
                                 *keys, **options)

        if options.get('whoami'):
            return ("(&(objectclass=posixaccount)(krbprincipalname=%s))"%\
                        getattr(context, 'principal'), base_dn, scope)

        preserved = options.get('preserved', False)
        if preserved is None:
            base_dn = self.api.env.basedn
            scope = ldap.SCOPE_SUBTREE
        elif preserved:
            base_dn = DN(self.obj.delete_container_dn, self.api.env.basedn)
        else:
            base_dn = DN(self.obj.active_container_dn, self.api.env.basedn)

        return (filter, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated

        if options.get('preserved', False) is None:
            base_dns = (
                DN(self.obj.active_container_dn, self.api.env.basedn),
                DN(self.obj.delete_container_dn, self.api.env.basedn),
            )
            entries[:] = list(
                e for e in entries if any(e.dn.endswith(bd) for bd in base_dns)
            )

        self.post_common_callback(ldap, entries, lockout=False, **options)
        for entry in entries:
            self.obj.get_preserved_attribute(entry, options)

        return truncated


@register()
class user_show(baseuser_show):
    __doc__ = _('Display information about a user.')

    has_output_params = baseuser_show.has_output_params + user_output_params
    takes_options = baseuser_show.takes_options + (
        Str('out?',
            doc=_('file to store certificate in'),
        ),
    )

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        dn = self.obj.get_either_dn(*keys, **options)
        self.pre_common_callback(ldap, dn, attrs_list, *keys, **options)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        convert_nsaccountlock(entry_attrs)
        self.post_common_callback(ldap, dn, entry_attrs, *keys, **options)
        self.obj.get_preserved_attribute(entry_attrs, options)
        return dn


@register()
class user_undel(LDAPQuery):
    __doc__ = _('Undelete a delete user account.')

    has_output = output.standard_value
    msg_summary = _('Undeleted user account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        # First check that the user exists and is a delete one
        delete_dn = self.obj.get_either_dn(*keys, **options)
        try:
            self._exc_wrapper(keys, options, ldap.get_entry)(delete_dn)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)
        if delete_dn.endswith(DN(self.obj.active_container_dn,
                                 api.env.basedn)):
            raise errors.InvocationError(
                message=_('user "%s" is already active') % keys[-1])

        active_dn = DN(delete_dn[0], self.obj.active_container_dn, api.env.basedn)

        # start to move the entry to the Active container
        self._exc_wrapper(keys, options, ldap.move_entry)(delete_dn, active_dn, del_old=True)

        # add the user we just undelete into the default primary group
        config = ldap.get_ipa_config()
        def_primary_group = config.get('ipadefaultprimarygroup')
        group_dn = self.api.Object['group'].get_dn(def_primary_group)

        # if the user is already a member of default primary group,
        # do not raise error
        # this can happen if automember rule or default group is set
        try:
            ldap.add_entry_to_group(active_dn, group_dn)
        except errors.AlreadyGroupMember:
            pass

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class user_stage(LDAPMultiQuery):
    __doc__ = _('Move deleted user into staged area')

    has_output = output.standard_multi_delete
    msg_summary = _('Staged user account "%(value)s"')

    # when moving from preserved to stage, some attributes may be
    # present in the preserved entry but cannot be provided to
    # stageuser_add
    # For instance: dn and uid are derived from LOGIN argument
    #    has_keytab, has_password, preserved are virtual attributes
    #    ipauniqueid, krbcanonicalname, sshpubkeyfp, krbextradata
    #    are automatically generated
    #    ipacertmapdata can only be provided with user_add_certmapdata
    ignore_attrs = [u'dn', u'uid',
                    u'has_keytab', u'has_password', u'preserved',
                    u'ipauniqueid', u'krbcanonicalname',
                    u'sshpubkeyfp', u'krbextradata',
                    u'ipacertmapdata',
                    u'nsaccountlock']

    def execute(self, *keys, **options):

        def _build_setattr_arg(key, val):
            if isinstance(val, bytes):
                return u"{}={}".format(key, val.decode('UTF-8'))
            else:
                return u"{}={}".format(key, val)

        staged = []
        failed = []

        for key in keys[-1]:
            single_keys = keys[:-1] + (key,)
            multi_keys = keys[:-1] + ((key,),)

            user = self.api.Command.user_show(*single_keys, all=True)['result']
            new_options = {}
            for param in self.api.Command.stageuser_add.options():
                try:
                    value = user[param.name]
                except KeyError:
                    continue
                if param.multivalue and not isinstance(value, (list, tuple)):
                    value = [value]
                elif not param.multivalue and isinstance(value, (list, tuple)):
                    value = value[0]
                new_options[param.name] = value

            # Some attributes may not be accessible through the Command
            # options and need to be added with --setattr
            set_attr = []
            for userkey in user.keys():
                if userkey in new_options or userkey in self.ignore_attrs:
                    continue
                value = user[userkey]

                if isinstance(value, (list, tuple)):
                    for val in value:
                        set_attr.append(_build_setattr_arg(userkey, val))
                else:
                    set_attr.append(_build_setattr_arg(userkey, val))
            if set_attr:
                new_options[u'setattr'] = set_attr

            try:
                self.api.Command.stageuser_add(*single_keys, **new_options)
                # special handling for certmapdata
                certmapdata = user.get(u'ipacertmapdata')
                if certmapdata:
                    self.api.Command.stageuser_add_certmapdata(
                        *single_keys,
                        ipacertmapdata=certmapdata)
                try:
                    self.api.Command.user_del(*multi_keys, preserve=False)
                except errors.ExecutionError:
                    self.api.Command.stageuser_del(*multi_keys)
                    raise
            except errors.ExecutionError:
                if not options['continue']:
                    raise
                failed.append(key)
            else:
                staged.append(key)

        return dict(
            result=dict(
                failed=pkey_to_value(failed, options),
            ),
            value=pkey_to_value(staged, options),
        )


@register()
class user_disable(LDAPQuery):
    __doc__ = _('Disable a user account.')

    has_output = output.standard_value
    msg_summary = _('Disabled user account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        check_protected_member(keys[-1])

        dn = self.obj.get_either_dn(*keys, **options)
        ldap.deactivate_entry(dn)

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class user_enable(LDAPQuery):
    __doc__ = _('Enable a user account.')

    has_output = output.standard_value
    has_output_params = LDAPQuery.has_output_params + user_output_params
    msg_summary = _('Enabled user account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_either_dn(*keys, **options)

        ldap.activate_entry(dn)

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class user_unlock(LDAPQuery):
    __doc__ = _("""
    Unlock a user account

    An account may become locked if the password is entered incorrectly too
    many times within a specific time period as controlled by password
    policy. A locked account is a temporary condition and may be unlocked by
    an administrator.""")

    has_output = output.standard_value
    msg_summary = _('Unlocked account "%(value)s"')

    def execute(self, *keys, **options):
        dn = self.obj.get_either_dn(*keys, **options)
        entry = self.obj.backend.get_entry(
            dn, ['krbLastAdminUnlock', 'krbLoginFailedCount'])

        entry['krbLastAdminUnlock'] = [strftime("%Y%m%d%H%M%SZ", gmtime())]
        entry['krbLoginFailedCount'] = ['0']

        self.obj.backend.update_entry(entry)

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class userstatus(LDAPObject):
    parent_object = 'user'

    takes_params = (
        Bool('preserved?',
            label=_('Preserved user'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('server',
            label=_('Server'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str('krbloginfailedcount',
            label=_('Failed logins'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str('krblastsuccessfulauth',
            label=_('Last successful authentication'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str('krblastfailedauth',
            label=_('Last failed authentication'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str('now',
            label=_('Time now'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
    )


@register()
class user_status(LDAPQuery):
    __doc__ = _("""
    Lockout status of a user account

    An account may become locked if the password is entered incorrectly too
    many times within a specific time period as controlled by password
    policy. A locked account is a temporary condition and may be unlocked by
    an administrator.

    This connects to each IPA master and displays the lockout status on
    each one.

    To determine whether an account is locked on a given server you need
    to compare the number of failed logins and the time of the last failure.
    For an account to be locked it must exceed the maxfail failures within
    the failinterval duration as specified in the password policy associated
    with the user.

    The failed login counter is modified only when a user attempts a log in
    so it is possible that an account may appear locked but the last failed
    login attempt is older than the lockouttime of the password policy. This
    means that the user may attempt a login again. """)

    obj_name = 'userstatus'
    attr_name = 'find'

    has_output = output.standard_list_of_entries

    def get_args(self):
        for arg in super(user_status, self).get_args():
            if arg.name == 'useruid':
                arg = arg.clone(cli_name='login')
            yield arg

    def execute(self, *keys, **options):
        ldap = self.obj.backend
        dn = self.api.Object.user.get_either_dn(*keys, **options)
        attr_list = ['krbloginfailedcount', 'krblastsuccessfulauth', 'krblastfailedauth', 'nsaccountlock']

        disabled = False
        masters = get_masters(ldap)

        entries = []
        count = 0
        for host in masters:
            if host == api.env.host:
                other_ldap = self.obj.backend
            else:
                try:
                    other_ldap = LDAPClient(ldap_uri='ldap://%s' % host)
                    other_ldap.gssapi_bind()
                except Exception as e:
                    logger.error("user_status: Connecting to %s failed with "
                                 "%s", host, str(e))
                    newresult = {'dn': dn}
                    newresult['server'] = _("%(host)s failed: %(error)s") % dict(host=host, error=str(e))
                    entries.append(newresult)
                    count += 1
                    continue
            try:
                entry = other_ldap.get_entry(dn, attr_list)
                newresult = {'dn': dn}
                for attr in ['krblastsuccessfulauth', 'krblastfailedauth']:
                    newresult[attr] = entry.get(attr, [u'N/A'])
                newresult['krbloginfailedcount'] = entry.get('krbloginfailedcount', u'0')
                if not options.get('raw', False):
                    for attr in ['krblastsuccessfulauth', 'krblastfailedauth']:
                        try:
                            if newresult[attr][0] == u'N/A':
                                continue
                            newtime = time.strptime(newresult[attr][0], '%Y%m%d%H%M%SZ')
                            newresult[attr][0] = unicode(time.strftime('%Y-%m-%dT%H:%M:%SZ', newtime))
                        except Exception as e:
                            logger.debug("time conversion failed with %s",
                                         str(e))
                newresult['server'] = host
                if options.get('raw', False):
                    time_format = '%Y%m%d%H%M%SZ'
                else:
                    time_format = '%Y-%m-%dT%H:%M:%SZ'
                newresult['now'] = unicode(strftime(time_format, gmtime()))
                convert_nsaccountlock(entry)
                if 'nsaccountlock' in entry:
                    disabled = entry['nsaccountlock']
                self.api.Object.user.get_preserved_attribute(entry, options)
                entries.append(newresult)
                count += 1
            except errors.NotFound:
                raise self.api.Object.user.handle_not_found(*keys)
            except Exception as e:
                logger.error("user_status: Retrieving status for %s failed "
                             "with %s", dn, str(e))
                newresult = {'dn': dn}
                newresult['server'] = _("%(host)s failed") % dict(host=host)
                entries.append(newresult)
                count += 1

            if host != api.env.host:
                other_ldap.close()

        return dict(result=entries,
                    count=count,
                    truncated=False,
                    summary=unicode(_('Account disabled: %(disabled)s' %
                        dict(disabled=disabled))),
        )


@register()
class user_add_cert(baseuser_add_cert):
    __doc__ = _('Add one or more certificates to the user entry')
    msg_summary = _('Added certificates to user "%(value)s"')


@register()
class user_remove_cert(baseuser_remove_cert):
    __doc__ = _('Remove one or more certificates to the user entry')
    msg_summary = _('Removed certificates from user "%(value)s"')


@register()
class user_add_certmapdata(baseuser_add_certmapdata):
    __doc__ = _("Add one or more certificate mappings to the user entry.")


@register()
class user_remove_certmapdata(baseuser_remove_certmapdata):
    __doc__ = _("Remove one or more certificate mappings from the user entry.")


@register()
class user_add_manager(baseuser_add_manager):
    __doc__ = _("Add a manager to the user entry")


@register()
class user_remove_manager(baseuser_remove_manager):
    __doc__ = _("Remove a manager to the user entry")


@register()
class user_add_principal(baseuser_add_principal):
    __doc__ = _('Add new principal alias to the user entry')
    msg_summary = _('Added new aliases to user "%(value)s"')


@register()
class user_remove_principal(baseuser_remove_principal):
    __doc__ = _('Remove principal alias from the user entry')
    msg_summary = _('Removed aliases from user "%(value)s"')
