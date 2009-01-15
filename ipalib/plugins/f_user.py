# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Frontend plugins for user (Identity).
"""

from ipalib import api, crud, errors
from ipalib import Object, Command  # Plugin base classes
from ipalib import Str, Password, Flag, Int  # Parameter types


def display_user(user):
    # FIXME: for now delete dn here. In the future pass in the kw to
    # output_for_cli()
    attr = sorted(user.keys())
    # Always have sn following givenname
    try:
        l = attr.index('givenname')
        attr.remove('sn')
        attr.insert(l+1, 'sn')
    except ValueError:
        pass

    for a in attr:
        if a != 'dn':
            print "%s: %s" % (a, user[a])

default_attributes = ['uid','givenname','sn','homeDirectory','loginshell']


class user(Object):
    """
    User object.
    """

    takes_params = (
        Str('givenname',
            cli_name='first',
            doc="User's first name",
        ),
        Str('sn',
            cli_name='last',
            doc="User's last name",
        ),
        Str('uid',
            cli_name='user',
            primary_key=True,
            default_from=lambda givenname, sn: givenname[0] + sn,
            normalizer=lambda value: value.lower(),
        ),
        Str('gecos?',
            doc='GECOS field',
            default_from=lambda uid: uid,
        ),
        Str('homedirectory?',
            cli_name='home',
            doc="User's home directory",
            default_from=lambda uid: '/home/%s' % uid,
        ),
        Str('loginshell?',
            cli_name='shell',
            default=u'/bin/sh',
            doc="User's Login shell",
        ),
        Str('krbprincipalname?',
            cli_name='principal',
            doc="User's Kerberos Principal name",
            default_from=lambda uid: '%s@%s' % (uid, api.env.realm),
        ),
        Str('mailaddress?',
            cli_name='email',
            doc="User's e-mail address",
        ),
        Password('userpassword?',
            cli_name='password',
            doc="Set user's password",
        ),
        Str('groups?',
            doc='Add account to one or more groups (comma-separated)',
        ),
        Int('uidnumber?',
            cli_name='uid',
            doc='The uid to use for this user. If not included one is automatically set.',
        ),
    )

api.register(user)


class user_add(crud.Add):
    'Add a new user.'

    def execute(self, uid, **kw):
        """
        Execute the user-add operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry as it will be created in LDAP.

        :param uid: The login name of the user being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'uid' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        kw['uid'] = uid
        kw['dn'] = ldap.make_user_dn(uid)

        # FIXME: enforce this elsewhere
#        if servercore.uid_too_long(kw['uid']):
#            raise errors.UsernameTooLong

        # Get our configuration
        config = ldap.get_ipa_config()

        # Let us add in some missing attributes
        if kw.get('homedirectory') is None:
            kw['homedirectory'] = '%s/%s' % (config.get('ipahomesrootdir'), kw.get('uid'))
            kw['homedirectory'] = kw['homedirectory'].replace('//', '/')
            kw['homedirectory'] = kw['homedirectory'].rstrip('/')
        if kw.get('loginshell') is None:
            kw['loginshell'] = config.get('ipadefaultloginshell')
        if kw.get('gecos') is None:
            kw['gecos'] = kw['uid']

        # If uidnumber is blank the the FDS dna_plugin will automatically
        # assign the next value. So we don't have to do anything with it.

        if not kw.get('gidnumber'):
            try:
                group_dn = ldap.find_entry_dn("cn", config.get('ipadefaultprimarygroup'))
                default_group = ldap.retrieve(group_dn, ['dn','gidNumber'])
                if default_group:
                    kw['gidnumber'] = default_group.get('gidnumber')
            except errors.NotFound:
                # Fake an LDAP error so we can return something useful to the kw
                raise errors.NotFound, "The default group for new kws, '%s', cannot be found." % config.get('ipadefaultprimarygroup')
            except Exception, e:
                # catch everything else
                raise e

        if kw.get('krbprincipalname') is None:
            kw['krbprincipalname'] = "%s@%s" % (kw.get('uid'), self.api.env.realm)

        # FIXME. This is a hack so we can request separate First and Last
        # name in the GUI.
        if kw.get('cn') is None:
            kw['cn'] = "%s %s" % (kw.get('givenname'),
                                           kw.get('sn'))

        # some required objectclasses
        kw['objectClass'] =  config.get('ipauserobjectclasses')

        return ldap.create(**kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Added user "%s"' % result['uid'])

api.register(user_add)


class user_del(crud.Del):
    'Delete an existing user.'

    def execute(self, uid, **kw):
        """Delete a user. Not to be confused with inactivate_user. This
           makes the entry go away completely.

           uid is the uid of the user to delete

           The memberOf plugin handles removing the user from any other
           groups.

           :param uid: The login name of the user being added.
           :param kw: Not used.
        """
        if uid == "admin":
            # FIXME: do we still want a "special" user?
            raise SyntaxError("admin required")
#            raise ipaerror.gen_exception(ipaerror.INPUT_ADMIN_REQUIRED)
        self.log.info("IPA: user-del '%s'" % uid)

        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("uid", uid)
        return ldap.delete(dn)

    def output_for_cli(self, textui, result, uid):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain('Deleted user "%s"' % uid)

api.register(user_del)


class user_mod(crud.Mod):
    'Edit an existing user.'
    def execute(self, uid, **kw):
        """
        Execute the user-mod operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param uid: The login name of the user to retrieve.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'uid' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("uid", uid)
        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, uid, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Updated user "%s"' % result['uid'])

api.register(user_mod)


class user_find(crud.Find):
    'Search the users.'
    takes_options = (
        Flag('all', doc='Retrieve all user attributes'),
    )
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap

        # Pull the list of searchable attributes out of the configuration.
        config = ldap.get_ipa_config()
        search_fields_conf_str = config.get('ipausersearchfields')
        search_fields = search_fields_conf_str.split(",")

        search_kw = {}
        for s in search_fields:
            search_kw[s] = term

        object_type = ldap.get_object_type("uid")
        if object_type and not kw.get('objectclass'):
            search_kw['objectclass'] = object_type
        if kw.get('all', False):
            search_kw['attributes'] = ['*']
        else:
            search_kw['attributes'] = default_attributes
        return ldap.search(**search_kw)

    def output_for_cli(self, textui, result, uid, **options):
        counter = result[0]
        users = result[1:]
        if counter == 0 or len(users) == 0:
            textui.print_plain("No entries found")
            return
        if len(users) == 1:
            textui.print_entry(users[0])
            return
        textui.print_name(self.name)
        for u in users:
            gn = u.get('givenname', '')
            sn= u.get('sn', '')
            textui.print_plain('%s %s:' % (gn, sn))
            textui.print_entry(u)
            textui.print_plain('')
        if counter == -1:
            textui.print_plain('These results are truncated.')
            textui.print_plain('Please refine your search and try again.')
        textui.print_count(users, '%d users matched')

api.register(user_find)


class user_show(crud.Get):
    'Examine an existing user.'
    takes_options = (
        Flag('all', doc='Retrieve all user attributes'),
    )
    def execute(self, uid, **kw):
        """
        Execute the user-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param uid: The login name of the user to retrieve.
        :param kw: "all" set to True = return all attributes
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("uid", uid)
        # FIXME: should kw contain the list of attributes to display?
        if kw.get('all', False):
            return ldap.retrieve(dn)
        else:
            return ldap.retrieve(dn, default_attributes)

    def output_for_cli(self, textui, result, uid, **options):
        if result:
            display_user(result)

api.register(user_show)

class user_lock(Command):
    'Lock a user account.'

    takes_args = (
        Str('uid', primary_key=True),
    )

    def execute(self, uid, **kw):
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("uid", uid)
        return ldap.mark_entry_inactive(dn)

    def output_for_cli(self, textui, result, uid):
        if result:
            textui.print_plain('Locked user "%s"' % uid)

api.register(user_lock)


class user_unlock(Command):
    'Unlock a user account.'

    takes_args = (
        Str('uid', primary_key=True),
    )

    def execute(self, uid, **kw):
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("uid", uid)
        return ldap.mark_entry_active(dn)

    def output_for_cli(self, textui, result, uid):
        if result:
            textui.print_plain('Unlocked user "%s"' % uid)

api.register(user_unlock)
