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

from time import gmtime, strftime
import string
import posixpath
import os

from ipalib import api, errors
from ipalib import Flag, Int, Password, Str, Bool, StrEnum, DateTime
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import *
from ipalib.plugins import baseldap
from ipalib.request import context
from ipalib import _, ngettext
from ipalib import output
from ipaplatform.paths import paths
from ipapython.ipautil import ipa_generate_password
from ipapython.ipavalidate import Email
from ipalib.capabilities import client_has_capability
from ipalib.util import (normalize_sshpubkey, validate_sshpubkey,
    convert_sshpubkey_post)
if api.env.in_server and api.env.context in ['lite', 'server']:
    from ipaserver.plugins.ldap2 import ldap2

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

register = Registry()

NO_UPG_MAGIC = '__no_upg__'

user_output_params = (
    Flag('has_keytab',
        label=_('Kerberos keys available'),
    ),
    Str('sshpubkeyfp*',
        label=_('SSH public key fingerprint'),
    ),
   )

status_output_params = (
    Str('server',
        label=_('Server'),
    ),
    Str('krbloginfailedcount',
        label=_('Failed logins'),
    ),
    Str('krblastsuccessfulauth',
        label=_('Last successful authentication'),
    ),
    Str('krblastfailedauth',
        label=_('Last failed authentication'),
    ),
    Str('now',
        label=_('Time now'),
    ),
   )

UPG_DEFINITION_DN = DN(('cn', 'UPG Definition'),
                       ('cn', 'Definitions'),
                       ('cn', 'Managed Entries'),
                       ('cn', 'etc'),
                       api.env.basedn)

# characters to be used for generating random user passwords
user_pwdchars = string.digits + string.ascii_letters + '_,.@+-='

def validate_nsaccountlock(entry_attrs):
    if 'nsaccountlock' in entry_attrs:
        nsaccountlock = entry_attrs['nsaccountlock']
        if not isinstance(nsaccountlock, (bool, Bool)):
            if not isinstance(nsaccountlock, basestring):
                raise errors.OnlyOneValueAllowed(attr='nsaccountlock')
            if nsaccountlock.lower() not in ('true', 'false'):
                raise errors.ValidationError(name='nsaccountlock',
                    error=_('must be TRUE or FALSE'))

def radius_dn2pk(api, entry_attrs):
    cl = entry_attrs.get('ipatokenradiusconfiglink', None)
    if cl:
        pk = api.Object['radiusproxy'].get_primary_key_from_dn(cl[0])
        entry_attrs['ipatokenradiusconfiglink'] = [pk]

def convert_nsaccountlock(entry_attrs):
    if not 'nsaccountlock' in entry_attrs:
        entry_attrs['nsaccountlock'] = False
    else:
        nsaccountlock = Bool('temp')
        entry_attrs['nsaccountlock'] = nsaccountlock.convert(entry_attrs['nsaccountlock'][0])

def split_principal(principal):
    """
    Split the principal into its components and do some basic validation.

    Automatically append our realm if it wasn't provided.
    """
    realm = None
    parts = principal.split('@')
    user = parts[0].lower()
    if len(parts) > 2:
        raise errors.MalformedUserPrincipal(principal=principal)

    if len(parts) == 2:
        realm = parts[1].upper()
        # At some point we'll support multiple realms
        if realm != api.env.realm:
            raise errors.RealmMismatch()
    else:
        realm = api.env.realm

    return (user, realm)

def validate_principal(ugettext, principal):
    """
    All the real work is done in split_principal.
    """
    (user, realm) = split_principal(principal)
    return None

def normalize_principal(principal):
    """
    Ensure that the name in the principal is lower-case. The realm is
    upper-case by convention but it isn't required.

    The principal is validated at this point.
    """
    (user, realm) = split_principal(principal)
    return unicode('%s@%s' % (user, realm))


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


def fix_addressbook_permission_bindrule(name, template, is_new,
                                        anonymous_read_aci,
                                        **other_options):
    """Fix bind rule type for Read User Addressbook/IPA Attributes permission

    When upgrading from an old IPA that had the global read ACI,
    or when installing the first replica with granular read permissions,
    we need to keep allowing anonymous access to many user attributes.
    This fixup_function changes the bind rule type accordingly.
    """
    if is_new and anonymous_read_aci:
        template['ipapermbindruletype'] = 'anonymous'


@register()
class user(LDAPObject):
    """
    User object.
    """
    container_dn = api.env.container_user
    object_name = _('user')
    object_name_plural = _('users')
    object_class = ['posixaccount']
    object_class_config = 'ipauserobjectclasses'
    possible_objectclasses = [
        'meporiginentry', 'ipauserauthtypeclass', 'ipauser',
        'ipatokenradiusproxyuser'
    ]
    disallow_object_classes = ['krbticketpolicyaux']
    permission_filter_objectclasses = ['posixaccount']
    search_attributes_config = 'ipausersearchfields'
    default_attributes = [
        'uid', 'givenname', 'sn', 'homedirectory', 'loginshell',
        'uidnumber', 'gidnumber', 'mail', 'ou',
        'telephonenumber', 'title', 'memberof', 'nsaccountlock',
        'memberofindirect', 'ipauserauthtype', 'userclass',
        'ipatokenradiusconfiglink', 'ipatokenradiususername',
        'krbprincipalexpiration'
    ]
    search_display_attributes = [
        'uid', 'givenname', 'sn', 'homedirectory', 'loginshell',
        'mail', 'telephonenumber', 'title', 'nsaccountlock',
        'uidnumber', 'gidnumber', 'sshpubkeyfp',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'memberof': ['group', 'netgroup', 'role', 'hbacrule', 'sudorule'],
        'memberofindirect': ['group', 'netgroup', 'role', 'hbacrule', 'sudorule'],
    }
    rdn_is_primary_key = True
    bindable = True
    password_attributes = [('userpassword', 'has_password'),
                           ('krbprincipalkey', 'has_keytab')]
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
                'fax', 'l', 'ou', 'st', 'postalcode', 'street',
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
                'sambantpassword', 'userpassword'
            },
            'replaces': [
                '(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(targetattr = "userpassword || krbprincipalkey || sambalmpassword || sambantpassword || passwordhistory")(version 3.0;acl "permission:Change a user password";allow (write) groupdn = "ldap:///cn=Change a user password,cn=permissions,cn=pbac,$SUFFIX";)',
                '(targetfilter = "(!(memberOf=cn=admins,cn=groups,cn=accounts,$SUFFIX))")(target = "ldap:///uid=*,cn=users,cn=accounts,$SUFFIX")(targetattr = "userpassword || krbprincipalkey || sambalmpassword || sambantpassword || passwordhistory")(version 3.0;acl "permission:Change a user password";allow (write) groupdn = "ldap:///cn=Change a user password,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {
                'User Administrators',
                'Modify Users and Reset passwords',
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
        'System: Modify Users': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'businesscategory', 'carlicense', 'cn', 'description',
                'displayname', 'employeetype', 'facsimiletelephonenumber',
                'gecos', 'givenname', 'homephone', 'inetuserhttpurl',
                'initials', 'l', 'labeleduri', 'loginshell', 'manager',
                'mepmanagedentry', 'mobile', 'objectclass', 'ou', 'pager',
                'postalcode', 'roomnumber', 'secretary', 'seealso', 'sn', 'st',
                'street', 'telephonenumber', 'title', 'userclass',
                'preferredlanguage',
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
    }

    label = _('Users')
    label_singular = _('User')

    takes_params = (
        Str('uid',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,252}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=255,
            cli_name='login',
            label=_('User login'),
            primary_key=True,
            default_from=lambda givenname, sn: givenname[0] + sn,
            normalizer=lambda value: value.lower(),
        ),
        Str('givenname',
            cli_name='first',
            label=_('First name'),
        ),
        Str('sn',
            cli_name='last',
            label=_('Last name'),
        ),
        Str('cn',
            label=_('Full name'),
            default_from=lambda givenname, sn: '%s %s' % (givenname, sn),
            autofill=True,
        ),
        Str('displayname?',
            label=_('Display name'),
            default_from=lambda givenname, sn: '%s %s' % (givenname, sn),
            autofill=True,
        ),
        Str('initials?',
            label=_('Initials'),
            default_from=lambda givenname, sn: '%c%c' % (givenname[0], sn[0]),
            autofill=True,
        ),
        Str('homedirectory?',
            cli_name='homedir',
            label=_('Home directory'),
        ),
        Str('gecos?',
            label=_('GECOS'),
            default_from=lambda givenname, sn: '%s %s' % (givenname, sn),
            autofill=True,
        ),
        Str('loginshell?',
            cli_name='shell',
            label=_('Login shell'),
        ),
        Str('krbprincipalname?', validate_principal,
            cli_name='principal',
            label=_('Kerberos principal'),
            default_from=lambda uid: '%s@%s' % (uid.lower(), api.env.realm),
            autofill=True,
            flags=['no_update'],
            normalizer=lambda value: normalize_principal(value),
        ),
        DateTime('krbprincipalexpiration?',
            cli_name='principal_expiration',
            label=_('Kerberos principal expiration'),
        ),
        Str('mail*',
            cli_name='email',
            label=_('Email address'),
        ),
        Password('userpassword?',
            cli_name='password',
            label=_('Password'),
            doc=_('Prompt to set the user password'),
            # FIXME: This is temporary till bug is fixed causing updates to
            # bomb out via the webUI.
            exclude='webui',
        ),
        Flag('random?',
            doc=_('Generate a random user password'),
            flags=('no_search', 'virtual_attribute'),
            default=False,
        ),
        Str('randompassword?',
            label=_('Random password'),
            flags=('no_create', 'no_update', 'no_search', 'virtual_attribute'),
        ),
        Int('uidnumber?',
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number (system will assign one if not provided)'),
            minvalue=1,
        ),
        Int('gidnumber?',
            label=_('GID'),
            doc=_('Group ID Number'),
            minvalue=1,
        ),
        Str('street?',
            cli_name='street',
            label=_('Street address'),
        ),
        Str('l?',
            cli_name='city',
            label=_('City'),
        ),
        Str('st?',
            cli_name='state',
            label=_('State/Province'),
        ),
        Str('postalcode?',
            label=_('ZIP'),
        ),
        Str('telephonenumber*',
            cli_name='phone',
            label=_('Telephone Number')
        ),
        Str('mobile*',
            label=_('Mobile Telephone Number')
        ),
        Str('pager*',
            label=_('Pager Number')
        ),
        Str('facsimiletelephonenumber*',
            cli_name='fax',
            label=_('Fax Number'),
        ),
        Str('ou?',
            cli_name='orgunit',
            label=_('Org. Unit'),
        ),
        Str('title?',
            label=_('Job Title'),
        ),
        Str('manager?',
            label=_('Manager'),
        ),
        Str('carlicense*',
            label=_('Car License'),
        ),
        Bool('nsaccountlock?',
            label=_('Account disabled'),
            flags=['no_option'],
        ),
        Str('ipasshpubkey*', validate_sshpubkey,
            cli_name='sshpubkey',
            label=_('SSH public key'),
            normalizer=normalize_sshpubkey,
            csv=True,
            flags=['no_search'],
        ),
        StrEnum('ipauserauthtype*',
            cli_name='user_auth_type',
            label=_('User authentication types'),
            doc=_('Types of supported user authentication'),
            values=(u'password', u'radius', u'otp'),
            csv=True,
        ),
        Str('userclass*',
            cli_name='class',
            label=_('Class'),
            doc=_('User category (semantics placed on this attribute are for '
                  'local interpretation)'),
        ),
        Str('ipatokenradiusconfiglink?',
            cli_name='radius',
            label=_('RADIUS proxy configuration'),
        ),
        Str('ipatokenradiususername?',
            cli_name='radius_username',
            label=_('RADIUS proxy username'),
        ),
        Str('departmentnumber*',
            label=_('Department Number'),
        ),
        Str('employeenumber?',
            label=_('Employee Number'),
        ),
        Str('employeetype?',
            label=_('Employee Type'),
        ),
        Str('preferredlanguage?',
            label=_('Preferred Language'),
            pattern='^(([a-zA-Z]{1,8}(-[a-zA-Z]{1,8})?(;q\=((0(\.[0-9]{0,3})?)|(1(\.0{0,3})?)))?' \
             + '(\s*,\s*[a-zA-Z]{1,8}(-[a-zA-Z]{1,8})?(;q\=((0(\.[0-9]{0,3})?)|(1(\.0{0,3})?)))?)*)|(\*))$',
            pattern_errmsg='must match RFC 2068 - 14.4, e.g., "da, en-gb;q=0.8, en;q=0.7"',
        ),
    )

    def _normalize_and_validate_email(self, email, config=None):
        if not config:
            config = self.backend.get_ipa_config()

        # check if default email domain should be added
        defaultdomain = config.get('ipadefaultemaildomain', [None])[0]
        if email:
            norm_email = []
            if not isinstance(email, (list, tuple)):
                email = [email]
            for m in email:
                if isinstance(m, basestring):
                    if '@' not in m and defaultdomain:
                        m = m + u'@' + defaultdomain
                    if not Email(m):
                        raise errors.ValidationError(name='email', error=_('invalid e-mail format: %(email)s') % dict(email=m))
                    norm_email.append(m)
                else:
                    if not Email(m):
                        raise errors.ValidationError(name='email', error=_('invalid e-mail format: %(email)s') % dict(email=m))
                    norm_email.append(m)
            return norm_email

        return email

    def _normalize_manager(self, manager):
        """
        Given a userid verify the user's existence and return the dn.
        """
        if not manager:
            return None

        if not isinstance(manager, list):
            manager = [manager]
        try:
            container_dn = DN(self.container_dn, api.env.basedn)
            for m in xrange(len(manager)):
                if isinstance(manager[m], DN) and manager[m].endswith(container_dn):
                    continue
                entry_attrs = self.backend.find_entry_by_attr(
                        self.primary_key.name, manager[m], self.object_class, [''],
                        container_dn
                    )
                manager[m] = entry_attrs.dn
        except errors.NotFound:
            raise errors.NotFound(reason=_('manager %(manager)s not found') % dict(manager=manager[m]))

        return manager

    def _convert_manager(self, entry_attrs, **options):
        """
        Convert a manager dn into a userid
        """
        if options.get('raw', False):
             return

        if 'manager' in entry_attrs:
            for m in xrange(len(entry_attrs['manager'])):
                entry_attrs['manager'][m] = self.get_primary_key_from_dn(entry_attrs['manager'][m])


@register()
class user_add(LDAPCreate):
    __doc__ = _('Add a new user.')

    msg_summary = _('Added user "%(value)s"')

    has_output_params = LDAPCreate.has_output_params + user_output_params

    takes_options = LDAPCreate.takes_options + (
        Flag('noprivate',
            cli_name='noprivate',
            doc=_('Don\'t create user private group'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if not options.get('noprivate', False):
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
        default_shell = config.get('ipadefaultloginshell', [paths.SH])[0]
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
            entry_attrs['userpassword'] = ipa_generate_password(user_pwdchars)
            # save the password so it can be displayed in post_callback
            setattr(context, 'randompassword', entry_attrs['userpassword'])

        if 'mail' in entry_attrs:
            entry_attrs['mail'] = self.obj._normalize_and_validate_email(entry_attrs['mail'], config)
        else:
            # No e-mail passed in. If we have a default e-mail domain set
            # then we'll add it automatically.
            defaultdomain = config.get('ipadefaultemaildomain', [None])[0]
            if defaultdomain:
                entry_attrs['mail'] = self.obj._normalize_and_validate_email(keys[-1], config)

        if 'manager' in entry_attrs:
            entry_attrs['manager'] = self.obj._normalize_manager(entry_attrs['manager'])

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

        self.obj._convert_manager(entry_attrs, **options)
        # delete description attribute NO_UPG_MAGIC if present
        if options.get('noprivate', False):
            if not options.get('all', False):
                desc_attr = ldap.get_entry(dn, ['description'])
                entry_attrs.update(desc_attr)
            if 'description' in entry_attrs and NO_UPG_MAGIC in entry_attrs['description']:
                entry_attrs['description'].remove(NO_UPG_MAGIC)
                kw = {'setattr': unicode('description=%s' % ','.join(entry_attrs['description']))}
                try:
                    self.api.Command['user_mod'](keys[-1], **kw)
                except (errors.EmptyModlist, errors.NotFound):
                    pass

        # Fetch the entry again to update memberof, mep data, etc updated
        # at the end of the transaction.
        newentry = ldap.get_entry(dn, ['*'])
        entry_attrs.update(newentry)

        if options.get('random', False):
            try:
                entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
            except AttributeError:
                # if both randompassword and userpassword options were used
                pass

        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        convert_sshpubkey_post(ldap, dn, entry_attrs)
        radius_dn2pk(self.api, entry_attrs)
        return dn


@register()
class user_del(LDAPDelete):
    __doc__ = _('Delete a user.')

    msg_summary = _('Deleted user "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        check_protected_member(keys[-1])

        # Delete all tokens owned and managed by this user.
        # Orphan all tokens owned but not managed by this user.
        owner = self.api.Object.user.get_primary_key_from_dn(dn)
        results = self.api.Command.otptoken_find(ipatokenowner=owner)['result']
        for token in results:
            orphan = not [x for x in token.get('managedby_user', []) if x == owner]
            token = self.api.Object.otptoken.get_primary_key_from_dn(token['dn'])
            if orphan:
                self.api.Command.otptoken_mod(token, ipatokenowner=None)
            else:
                self.api.Command.otptoken_del(token)

        return dn


@register()
class user_mod(LDAPUpdate):
    __doc__ = _('Modify a user.')

    msg_summary = _('Modified user "%(value)s"')

    has_output_params = LDAPUpdate.has_output_params + user_output_params

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if options.get('rename') is not None:
            config = ldap.get_ipa_config()
            if 'ipamaxusernamelength' in config:
                if len(options['rename']) > int(config.get('ipamaxusernamelength')[0]):
                    raise errors.ValidationError(
                        name=self.obj.primary_key.cli_name,
                        error=_('can be at most %(len)d characters') % dict(
                            len = int(config.get('ipamaxusernamelength')[0])
                        )
                    )
        if 'mail' in entry_attrs:
            entry_attrs['mail'] = self.obj._normalize_and_validate_email(entry_attrs['mail'])
        if 'manager' in entry_attrs:
            entry_attrs['manager'] = self.obj._normalize_manager(entry_attrs['manager'])
        validate_nsaccountlock(entry_attrs)
        if 'userpassword' not in entry_attrs and options.get('random'):
            entry_attrs['userpassword'] = ipa_generate_password(user_pwdchars)
            # save the password so it can be displayed in post_callback
            setattr(context, 'randompassword', entry_attrs['userpassword'])
        if ('ipasshpubkey' in entry_attrs or 'ipauserauthtype' in entry_attrs
            or 'userclass' in entry_attrs or 'ipatokenradiusconfiglink' in entry_attrs):
            if 'objectclass' in entry_attrs:
                obj_classes = entry_attrs['objectclass']
            else:
                _entry_attrs = ldap.get_entry(dn, ['objectclass'])
                obj_classes = entry_attrs['objectclass'] = _entry_attrs['objectclass']

            if 'ipasshpubkey' in entry_attrs and 'ipasshuser' not in obj_classes:
                obj_classes.append('ipasshuser')

            if 'ipauserauthtype' in entry_attrs and 'ipauserauthtypeclass' not in obj_classes:
                obj_classes.append('ipauserauthtypeclass')

            if 'userclass' in entry_attrs and 'ipauser' not in obj_classes:
                obj_classes.append('ipauser')

            if 'ipatokenradiusconfiglink' in entry_attrs:
                cl = entry_attrs['ipatokenradiusconfiglink']
                if cl:
                    if 'ipatokenradiusproxyuser' not in obj_classes:
                        obj_classes.append('ipatokenradiusproxyuser')

                    answer = self.api.Object['radiusproxy'].get_dn_if_exists(cl)
                    entry_attrs['ipatokenradiusconfiglink'] = answer

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        if options.get('random', False):
            try:
                entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
            except AttributeError:
                # if both randompassword and userpassword options were used
                pass
        convert_nsaccountlock(entry_attrs)
        self.obj._convert_manager(entry_attrs, **options)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        convert_sshpubkey_post(ldap, dn, entry_attrs)
        radius_dn2pk(self.api, entry_attrs)
        return dn


@register()
class user_find(LDAPSearch):
    __doc__ = _('Search for users.')

    member_attributes = ['memberof']
    has_output_params = LDAPSearch.has_output_params + user_output_params

    takes_options = LDAPSearch.takes_options + (
        Flag('whoami',
            label=_('Self'),
            doc=_('Display user record for current Kerberos principal'),
        ),
    )

    def execute(self, *args, **options):
        # assure the manager attr is a dn, not just a bare uid
        manager = options.get('manager')
        if manager is not None:
            options['manager'] = self.obj._normalize_manager(manager)

        # Ensure that the RADIUS config link is a dn, not just the name
        cl = 'ipatokenradiusconfiglink'
        if cl in options:
            options[cl] = self.api.Object['radiusproxy'].get_dn(options[cl])

        return super(user_find, self).execute(self, *args, **options)

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *keys, **options):
        assert isinstance(base_dn, DN)
        if options.get('whoami'):
            return ("(&(objectclass=posixaccount)(krbprincipalname=%s))"%\
                        getattr(context, 'principal'), base_dn, scope)

        return (filter, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        for attrs in entries:
            self.obj._convert_manager(attrs, **options)
            self.obj.get_password_attributes(ldap, attrs.dn, attrs)
            convert_nsaccountlock(attrs)
            convert_sshpubkey_post(ldap, attrs.dn, attrs)
        return truncated

    msg_summary = ngettext(
        '%(count)d user matched', '%(count)d users matched', 0
    )


@register()
class user_show(LDAPRetrieve):
    __doc__ = _('Display information about a user.')

    has_output_params = LDAPRetrieve.has_output_params + user_output_params

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        convert_nsaccountlock(entry_attrs)
        self.obj._convert_manager(entry_attrs, **options)
        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        convert_sshpubkey_post(ldap, dn, entry_attrs)
        radius_dn2pk(self.api, entry_attrs)
        return dn


@register()
class user_disable(LDAPQuery):
    __doc__ = _('Disable a user account.')

    has_output = output.standard_value
    msg_summary = _('Disabled user account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        check_protected_member(keys[-1])

        dn = self.obj.get_dn(*keys, **options)
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

        dn = self.obj.get_dn(*keys, **options)

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
        dn = self.obj.get_dn(*keys, **options)
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

    has_output = output.standard_list_of_entries
    has_output_params = LDAPSearch.has_output_params + status_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend
        dn = self.obj.get_dn(*keys, **options)
        attr_list = ['krbloginfailedcount', 'krblastsuccessfulauth', 'krblastfailedauth', 'nsaccountlock']

        disabled = False
        masters = []
        # Get list of masters
        try:
            (masters, truncated) = ldap.find_entries(
                None, ['*'], DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn),
                ldap.SCOPE_ONELEVEL
            )
        except errors.NotFound:
            # If this happens we have some pretty serious problems
            self.error('No IPA masters found!')
            pass

        entries = []
        count = 0
        for master in masters:
            host = master['cn'][0]
            if host == api.env.host:
                other_ldap = self.obj.backend
            else:
                other_ldap = ldap2(shared_instance=False,
                                   ldap_uri='ldap://%s' % host,
                                   base_dn=self.api.env.basedn)
                try:
                    other_ldap.connect(ccache=os.environ['KRB5CCNAME'])
                except Exception, e:
                    self.error("user_status: Connecting to %s failed with %s" % (host, str(e)))
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
                        except Exception, e:
                            self.debug("time conversion failed with %s" % str(e))
                            pass
                newresult['server'] = host
                if options.get('raw', False):
                    time_format = '%Y%m%d%H%M%SZ'
                else:
                    time_format = '%Y-%m-%dT%H:%M:%SZ'
                newresult['now'] = unicode(strftime(time_format, gmtime()))
                convert_nsaccountlock(entry)
                if 'nsaccountlock' in entry:
                    disabled = entry['nsaccountlock']
                entries.append(newresult)
                count += 1
            except errors.NotFound:
                self.obj.handle_not_found(*keys)
            except Exception, e:
                self.error("user_status: Retrieving status for %s failed with %s" % (dn, str(e)))
                newresult = {'dn': dn}
                newresult['server'] = _("%(host)s failed") % dict(host=host)
                entries.append(newresult)
                count += 1

            if host != api.env.host:
                other_ldap.destroy_connection()

        return dict(result=entries,
                    count=count,
                    truncated=False,
                    summary=unicode(_('Account disabled: %(disabled)s' %
                        dict(disabled=disabled))),
        )
