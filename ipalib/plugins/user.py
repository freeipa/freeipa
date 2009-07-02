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
Users (Identity)
"""

from ipalib import api, crud, errors
from ipalib import Command, Object
from ipalib import Flag, Int, Password, Str

# parent DN
_container_dn = api.env.container_user

# attributes displayed by default
_default_attributes = [
    'uid', 'givenname', 'sn', 'homedirectory', 'loginshell'
]


class user(Object):
    """
    User object.
    """

    takes_params = (
        Str('givenname',
            cli_name='first',
            doc='first name',
        ),
        Str('sn',
            cli_name='last',
            doc='last name',
        ),
        Str('uid',
            cli_name='user',
            doc='login name',
            primary_key=True,
            default_from=lambda givenname, sn: givenname[0] + sn,
            normalizer=lambda value: value.lower(),
        ),
        Str('gecos?',
            doc='GECOS field',
            default_from=lambda uid: uid,
        ),
        Str('homedirectory?',
            cli_name='homedir',
            doc='home directory',
            default_from=lambda uid: '/home/%s' % uid,
        ),
        Str('loginshell?',
            cli_name='shell',
            default=u'/bin/sh',
            doc='login shell',
        ),
        Str('krbprincipalname?',
            cli_name='principal',
            doc='Kerberos principal name',
            default_from=lambda uid: '%s@%s' % (uid, api.env.realm),
        ),
        Str('mail?',
            cli_name='email',
            doc='e-mail address',
        ),
        Password('userpassword?',
            cli_name='password',
            doc='password',
        ),
        Int('uidnumber?',
            cli_name='uid',
            doc='UID (use this option to set it manually)',
        ),
        Str('street?',
            cli_name='street',
            doc='street address',
        ),
    )

api.register(user)


class user_add(crud.Create):
    """
    Create new user.
    """

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2
        uid = args[0]

        # build entry attributes
        entry_attrs = self.args_options_2_entry(*args, **options)

        # build entry DN
        dn = ldap.make_dn(entry_attrs, 'uid', _container_dn)

        # get configuration entry attributes
        config = ldap.get_ipa_config()[1]

        # fill in required attributes
        entry_attrs['objectclass'] = config.get('ipauserobjectclasses')

        # fill default values
        # uidNumber gets filled automatically by the DS dna_plugin
        entry_attrs.setdefault('loginshell', config.get('ipadefaultloginshell'))
        entry_attrs.setdefault('gecos', uid)
        entry_attrs.setdefault(
            'krbprincipalname', '%s@%s' % (uid, self.api.env.realm)
        )
        # hack so we can request separate first and last name in CLI
        entry_attrs.setdefault(
            'cn', '%s %s' % (entry_attrs['givenname'], entry_attrs['sn'])
        )
        if 'homedirectory' not in entry_attrs:
            # get home's root directory from config
            homes_root = config.get('ipahomesrootdir', '/home')[0]
            # build user's home directory based on his uid
            home_dir = '%s/%s' % (homes_root, uid)
            home_dir = home_dir.replace('//', '/').rstrip('/')
            entry_attrs['homedirectory'] = home_dir

        # we're adding new users to a default group, get it's DN and gidNumber
        # get default group name from config
        def_primary_group = config.get('ipadefaultprimarygroup')
        # build the group's DN
        group_parent_dn = self.api.env.container_group
        group_rdn = ldap.make_rdn_from_attr('cn', def_primary_group)
        group_dn = ldap.make_dn_from_rdn(group_rdn, group_parent_dn)
        # try to retrieve the group's gidNumber
        try:
            (group_dn, group_attrs) = ldap.get_entry(group_dn, ['gidnumber'])
        except errors.NotFound:
            error_msg = 'Default group for new users not found.'
            raise errors.NotFound(reason=error_msg)
        # fill default group's gidNumber
        entry_attrs['gidnumber'] = group_attrs['gidnumber']

        # create user entry
        ldap.add_entry(dn, entry_attrs)

        # add user to default group
        ldap.add_entry_to_group(dn, group_dn)

        # get user entry with created attributes for output
        return ldap.get_entry(dn, entry_attrs.keys())

    def output_for_cli(self, textui, result, *args, **options):
        (dn, entry_attrs) = result
        uid = args[0]

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_dashed('Created user "%s".' % uid)

api.register(user_add)


class user_del(crud.Delete):
    """
    Delete user.
    """

    def execute(self, uid):
        ldap = self.api.Backend.ldap2

        if uid == 'admin':
            # FIXME: add a specific exception for this?
            raise errors.ExecutionError('Cannot delete user "admin".')

        # build entry DN
        rdn = ldap.make_rdn_from_attr('uid', uid)
        dn = ldap.make_dn_from_rdn(rdn, _container_dn)

        # delete user entry
        ldap.delete_entry(dn)

        # blog about it
        self.log.info('IPA: %s "%s"' % (self.name, uid))

        # return something positive
        return True

    def output_for_cli(self, textui, result, uid):
        textui.print_name(self.name)
        textui.print_dashed('Deleted user "%s".' % uid)

api.register(user_del)


class user_mod(crud.Update):
    """
    Modify user.
    """

    def execute(self, uid, **options):
        ldap = self.api.Backend.ldap2

        # build entry attributes, don't include uid!
        entry_attrs = self.args_options_2_entry(*tuple(), **options)

        # build entry DN
        rdn = ldap.make_rdn_from_attr('uid', uid)
        dn = ldap.make_dn_from_rdn(rdn, _container_dn)

        # update user entry
        ldap.update_entry(dn, entry_attrs)

        # get user entry with modified + default attributes for output
        return ldap.get_entry(dn, (entry_attrs.keys() + _default_attributes))

    def output_for_cli(self, textui, result, uid, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)
        textui.print_dashed('Modified user "%s".' % uid)

api.register(user_mod)


class user_find(crud.Search):
    """
    Search for users.
    """

    takes_options = (
        Flag('all',
            doc='retrieve all attributes?',
        ),
    )

    def execute(self, term, **options):
        ldap = self.api.Backend.ldap2

        # get list of search fields from config
        config = ldap.get_ipa_config()[1]
        search_fields = config.get('ipausersearchfields')[0].split(',')

        # look for term in all search fields
        search_kw = self.args_options_2_entry(**options)
        if term:
            for f in search_fields:
                search_kw[f] = '%s' % term
        # build search filter
        filter = ldap.make_filter(search_kw, exact=False)

        # select attributes we want to retrieve
        if options['all']:
            attrs_list = ['*']
        else:
            attrs_list = _default_attributes

        # get matching entries
        try:
            (entries, truncated) = ldap.find_entries(
                filter, attrs_list, _container_dn, ldap.SCOPE_ONELEVEL
            )
        except errors.NotFound:
            (entries, truncated) = (tuple(), False)

        return (entries, truncated)

    def output_for_cli(self, textui, result, term, **options):
        (entries, truncated) = result

        textui.print_name(self.name)
        for (dn, entry_attrs) in entries:
            textui.print_attribute('dn', dn)
            textui.print_entry(entry_attrs)
            textui.print_plain('')
        textui.print_count(
            len(entries), '%i user matched.', '%i users matched.'
        )
        if truncated:
            textui.print_dashed('These results are truncated.', below=False)
            textui.print_dashed(
                'Please refine your search and try again.', above=False
            )

api.register(user_find)


class user_show(crud.Retrieve):
    """
    Display user.
    """

    takes_options = (
        Flag('all',
            doc='retrieve all attributes?',
        ),
    )

    def execute(self, uid, **options):
        ldap = self.api.Backend.ldap2

        # build entry DN
        rdn = ldap.make_rdn_from_attr('uid', uid)
        dn = ldap.make_dn_from_rdn(rdn, _container_dn)

        # select attributes we want to retrieve
        if options['all']:
            attrs_list = ['*']
        else:
            attrs_list = _default_attributes

        return ldap.get_entry(dn, attrs_list)

    def output_for_cli(self, textui, result, uid, **options):
        (dn, entry_attrs) = result

        textui.print_name(self.name)
        textui.print_attribute('dn', dn)
        textui.print_entry(entry_attrs)

api.register(user_show)


class user_lock(Command):
    """
    Lock user account.
    """

    takes_args = (
        Str('uid',
            cli_name='user',
            doc='login name',
        ),
    )

    def execute(self, uid):
        ldap = self.api.Backend.ldap2

        # build entry DN
        rdn = ldap.make_rdn_from_attr('uid', uid)
        dn = ldap.make_dn_from_rdn(rdn, _container_dn)

        # lock!
        try:
            ldap.deactivate_entry(dn)
        except errors.AlreadyInactive:
            pass

        # return something positive
        return True

    def output_for_cli(self, textui, result, uid):
        textui.print_name(self.name)
        textui.print_dashed('Locked user "%s".' % uid)

api.register(user_lock)


class user_unlock(Command):
    """
    Unlock user account.
    """

    takes_args = (
        Str('uid',
            cli_name='user',
            doc='login name',
        ),
    )

    def execute(self, uid):
        ldap = self.api.Backend.ldap2

        # build entry DN
        rdn = ldap.make_rdn_from_attr('uid', uid)
        dn = ldap.make_dn_from_rdn(rdn, _container_dn)

        # unlock!
        try:
            ldap.activate_entry(dn)
        except errors.AlreadyActive:
            pass

        # return something positive
        return True

    def output_for_cli(self, textui, result, uid):
        textui.print_name(self.name)
        textui.print_dashed('Unlocked user "%s".' % uid)

api.register(user_unlock)

