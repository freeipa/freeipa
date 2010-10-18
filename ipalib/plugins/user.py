# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Users

Manage user entries. All users are POSIX users.

Locking a user account prevents that user from obtaining new Kerberos
credentials. It does not invalidate any credentials that have already
been issued.

EXAMPLES:

 Add a new user:
   ipa user-add --first=Tim --last=User --passwd tuser1

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
"""

from ipalib import api, errors
from ipalib import Flag, Int, Password, Str
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
from ipalib.request import context


class user(LDAPObject):
    """
    User object.
    """
    container_dn = api.env.container_user
    object_name = 'user'
    object_name_plural = 'users'
    object_class = ['posixaccount']
    object_class_config = 'ipauserobjectclasses'
    search_attributes_config = 'ipausersearchfields'
    default_attributes = [
        'uid', 'givenname', 'sn', 'homedirectory', 'loginshell', 'ou',
        'telephonenumber', 'title', 'memberof',
    ]
    uuid_attribute = 'ipauniqueid'
    attribute_members = {
        'memberof': ['group', 'netgroup', 'rolegroup', 'taskgroup'],
    }
    rdnattr = 'uid'

    label = _('Users')

    takes_params = (
        Str('uid',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,30}[a-zA-Z0-9_.$-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, . and $',
            maxlength=33,
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
        Str('homedirectory?',
            cli_name='homedir',
            label=('Home directory'),
            default_from=lambda uid: '/home/%s' % uid,
        ),
        Str('gecos?',
            label=_('GECOS field'),
            default_from=lambda uid: uid,
            autofill=True,
        ),
        Str('loginshell?',
            cli_name='shell',
            label=_('Login shell'),
            default=u'/bin/sh',
        ),
        Str('krbprincipalname?',
            cli_name='principal',
            label=_('Kerberos principal'),
            default_from=lambda uid: '%s@%s' % (uid, api.env.realm),
            autofill=True,
        ),
        Str('mail?',
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
        Int('uidnumber?',
            cli_name='uid',
            label=_('UID'),
            doc=_('User ID Number (system will assign one if not provided)'),
            autofill=True,
            default=999,
        ),
        Str('street?',
            cli_name='street',
            label=_('Street address'),
        ),
        Str('memberof_group?',
            label=_('Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberof_netgroup?',
            label=_('Netgroups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberof_rolegroup?',
            label=_('Rolegroups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberof_taskgroup?',
            label=_('Taskgroups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('telephonenumber*',
            cli_name='phone',
            label=_('Telephone Number') ),
        Str('mobile*',
            label=_('Mobile Telephone Number') ),
        Str('pager*',
            label=_('Pager Number') ),
        Str('facsimiletelephonenumber*',
            cli_name='fax',
            label=_('Fax Number') ),
    )

api.register(user)


class user_add(LDAPCreate):
    """
    Add a new user.
    """

    msg_summary = _('Added user "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        config = ldap.get_ipa_config()[1]
        if 'ipamaxusernamelength' in config:
            if len(keys[-1]) > int(config.get('ipamaxusernamelength')[0]):
                raise errors.ValidationError(name='uid', error=_('can be at most %(len)d characters' % dict(len = int(config.get('ipamaxusernamelength')[0]))))
        entry_attrs.setdefault('loginshell', config.get('ipadefaultloginshell'))
        # hack so we can request separate first and last name in CLI
        full_name = '%s %s' % (entry_attrs['givenname'], entry_attrs['sn'])
        entry_attrs.setdefault('cn', full_name)
        if 'homedirectory' not in entry_attrs:
            # get home's root directory from config
            homes_root = config.get('ipahomesrootdir', '/home')[0]
            # build user's home directory based on his uid
            home_dir = '%s/%s' % (homes_root, keys[-1])
            home_dir = home_dir.replace('//', '/').rstrip('/')
            entry_attrs['homedirectory'] = home_dir

        if ldap.has_upg():
            # User Private Groups - uidNumber == gidNumber
            entry_attrs['gidnumber'] = entry_attrs['uidnumber']
        else:
            # we're adding new users to a default group, get its gidNumber
            # get default group name from config
            def_primary_group = config.get('ipadefaultprimarygroup')
            group_dn = self.api.Object['group'].get_dn(def_primary_group)
            try:
                (group_dn, group_attrs) = ldap.get_entry(group_dn, ['gidnumber'])
            except errors.NotFound:
                error_msg = 'Default group for new users not found.'
                raise errors.NotFound(reason=error_msg)
            entry_attrs['gidnumber'] = group_attrs['gidnumber']

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        config = ldap.get_ipa_config()[1]
        # add the user we just created into the default primary group
        def_primary_group = config.get('ipadefaultprimarygroup')
        group_dn = self.api.Object['group'].get_dn(def_primary_group)
        ldap.add_entry_to_group(dn, group_dn)
        return dn

api.register(user_add)


class user_del(LDAPDelete):
    """
    Delete a user.
    """

    msg_summary = _('Deleted user "%(value)s"')

    def post_callback(self, ldap, dn, *keys, **options):
        self.log.info('IPA: %s "%s"' % (self.name, keys[-1]))
        return True

api.register(user_del)


class user_mod(LDAPUpdate):
    """
    Modify a user.
    """

    msg_summary = _('Modified user "%(value)s"')

api.register(user_mod)


class user_find(LDAPSearch):
    """
    Search for users.
    """

    takes_options = LDAPSearch.takes_options + (
        Flag('whoami',
            label=_('Self'),
            doc=_('Display user record for current Kerberos principal'),
        ),
    )
    def pre_callback(self, ldap, filter, entry_attrs, attrs_list, *keys, **options):
        if options.get('whoami'):
            return "(&(objectclass=posixaccount)(krbprincipalname=%s))"%\
                getattr(context, 'principal')
        return filter

    msg_summary = ngettext(
        '%(count)d user matched', '%(count)d users matched', 0
    )

api.register(user_find)


class user_show(LDAPRetrieve):
    """
    Display information about a user.
    """

api.register(user_show)


class user_disable(LDAPQuery):
    """
    Disable user account.
    """

    has_output = output.standard_value
    msg_summary = _('Disabled user account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        try:
            ldap.deactivate_entry(dn)
        except errors.AlreadyInactive:
            pass

        return dict(
            result=True,
            value=keys[0],
        )

api.register(user_disable)


class user_enable(LDAPQuery):
    """
    Enable user account.
    """

    has_output = output.standard_value
    msg_summary = _('Enabled user account "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        try:
            ldap.activate_entry(dn)
        except errors.AlreadyActive:
            pass

        return dict(
            result=True,
            value=keys[0],
        )

api.register(user_enable)
