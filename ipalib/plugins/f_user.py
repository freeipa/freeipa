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

from ipalib import frontend
from ipalib import crud
from ipalib.frontend import Param
from ipalib import api
from ipalib import errors
from ipalib import ipa_types
from ipa_server import servercore
from ipa_server import ipaldap
import ldap

# Command to get the idea how plugins will interact with api.env
class envtest(frontend.Command):
    'Show current environment.'
    def run(self, *args, **kw):
        print ""
        print "Environment variables:"
        for var in api.env:
            val = api.env[var]
            if var is 'server':
                print ""
                print "  Servers:"
                for item in api.env.server:
                    print "    %s" % item
                print ""
            else:
                print "  %s: %s" % (var, val)
        return {}
api.register(envtest)


class user(frontend.Object):
    """
    User object.
    """
    takes_params = (
        Param('givenname',
            cli_name='first',
            doc='User first name',
        ),
        Param('sn',
            cli_name='last',
            doc='User last name',
        ),
        Param('uid',
            cli_name='user',
            primary_key=True,
            default_from=lambda givenname, sn: givenname[0] + sn,
            normalize=lambda value: value.lower(),
        ),
        Param('gecos?',
            doc='GECOS field',
            default_from=lambda uid: uid,
        ),
        Param('homedirectory?',
            cli_name='home',
            doc='Path of user home directory',
            default_from=lambda uid: '/home/%s' % uid,
        ),
        Param('loginshell?',
            cli_name='shell',
            default=u'/bin/sh',
            doc='Login shell',
        ),
        Param('krbprincipalname?', cli_name='principal',
            default_from=lambda uid: '%s@EXAMPLE.COM' % uid,
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

        if servercore.uid_too_long(kw['uid']):
            raise errors.UsernameTooLong

        # Get our configuration
        config = servercore.get_ipa_config()

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

        group_dn="cn=%s,%s,%s" % (config.get('ipadefaultprimarygroup'), servercore.DefaultGroupContainer, servercore.basedn)
        try:
            default_group = servercore.get_entry_by_dn(group_dn, ['dn','gidNumber'])
            if default_group:
                kw['gidnumber'] = default_group.get('gidnumber')
        except errors.NotFound:
            # Fake an LDAP error so we can return something useful to the kw
            raise errors.NotFound, "The default group for new kws, '%s', cannot be found." % config.get('ipadefaultprimarygroup')
        except Exception, e:
            # catch everything else
            raise e

        if kw.get('krbprincipalname') is None:
            kw['krbprincipalname'] = "%s@%s" % (kw.get('uid'), servercore.realm)

        # FIXME. This is a hack so we can request separate First and Last
        # name in the GUI.
        if kw.get('cn') is None:
            kw['cn'] = "%s %s" % (kw.get('givenname'),
                                           kw.get('sn'))

        # some required objectclasses
        kw['objectClass'] =  config.get('ipauserobjectclasses')
<<<<<<< HEAD:ipalib/plugins/f_user.py
=======

        return ldap.create(**kw)
    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "User added"

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
#        logging.info("IPA: delete_user '%s'" % uid)
        user = servercore.get_user_by_uid(uid, ['dn', 'uid'])
        if not user:
            raise errors.NotFound

        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("uid", uid, ["*"], "posixAccount")
        return ldap.delete(dn)
    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "User deleted"

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
        dn = ldap.find_entry_dn("uid", uid, "posixAccount")
        return ldap.update(dn, **kw)

    def output_for_cli(self, ret):
        """
        Output result of this command to command line interface.
        """
        if ret:
            print "User updated"

api.register(user_mod)


class user_find(crud.Find):
    'Search the users.'
    def execute(self, *args, **kw):
        uid=args[0]
        result = servercore.find_users(uid, ["*"])
        return result
    def forward(self, *args, **kw):
        users = super(crud.Find, self).forward(*args, **kw)
        if not users:
            return
        counter = users[0]
        users = users[1:]
        if counter == 0:
            print "No entries found for", args[0]
            return
        elif counter == -1:
            print "These results are truncated."
            print "Please refine your search and try again."

        for u in users:
            for a in u.keys():
                print "%s: %s" % (a, u[a])
api.register(user_find)


class user_show(crud.Get):
    'Examine an existing user.'
    def execute(self, uid, **kw):
        """
        Execute the user-show operation.

        The dn should not be passed as a keyword argument as it is constructed
        by this method.

        Returns the entry

        :param uid: The login name of the user to retrieve.
        :param kw: Not used.
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("uid", uid, "posixAccount")
        # FIXME: should kw contain the list of attributes?
        return ldap.retrieve(dn)

api.register(user_show)

class user_lock(frontend.Command):
    'Lock a user account.'
    takes_args = (
        Param('uid', primary_key=True),
    )
    def execute(self, *args, **kw):
        uid = args[0]
        user = servercore.get_user_by_uid(uid, ['dn', 'uid'])
        return servercore.mark_entry_inactive(user['dn'])
    def forward(self, *args, **kw):
        result = super(user_lock, self).forward(*args, **kw)
        if result:
            print "User locked"
api.register(user_lock)

class user_unlock(frontend.Command):
    'Unlock a user account.'
    takes_args = (
        Param('uid', primary_key=True),
    )
    def execute(self, *args, **kw):
        uid = args[0]
        user = servercore.get_user_by_uid(uid, ['dn', 'uid'])
        return servercore.mark_entry_active(user['dn'])
    def forward(self, *args, **kw):
        result = super(user_unlock, self).forward(*args, **kw)
        if result:
            print "User unlocked"
api.register(user_unlock)
