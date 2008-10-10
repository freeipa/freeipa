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
api.register(envtest)


class user(frontend.Object):
    """
    User object.
    """
    takes_params = (
        'givenname',
        'sn',
        Param('uid',
            primary_key=True,
            default_from=lambda givenname, sn: givenname[0] + sn,
            normalize=lambda value: value.lower(),
        ),
        Param('krbprincipalname',
            default_from=lambda uid: '%s@EXAMPLE.COM' % uid,
        ),
        Param('homedirectory',
            default_from=lambda uid: '/home/%s' % uid,
        )
    )
api.register(user)


class user_add(crud.Add):
    'Add a new user.'
    def execute(self, *args, **kw):
        """args[0] = uid of the user to add
           kw{container} is the location in the DIT to add the user, not
           required
           kw otherwise contains all the attributes 
        """
        # FIXME: ug, really?
        if not kw.get('container'):
            user_container = servercore.DefaultUserContainer
        else:
            user_container = kw['container']
            del kw['container']

        user = kw

        user['uid'] = args[0]

        if servercore.user_exists(user['uid']):
            raise errors.Duplicate("user already exists")
        if servercore.uid_too_long(user['uid']):
            raise errors.UsernameTooLong

        # dn is set here, not by the user
        try:
            del user['dn']
        except KeyError:
            pass

        # No need to set empty fields, and they can cause issues when they
        # get to LDAP, like:
        #     TypeError: ('expected a string in the list', None)
        for k in user.keys():
            if not user[k] or len(user[k]) == 0 or (isinstance(user[k],list) and len(user[k]) == 1 and '' in user[k]):
                del user[k]

        dn="uid=%s,%s,%s" % (ldap.dn.escape_dn_chars(user['uid']),
                             user_container,servercore.basedn)

        entry = ipaldap.Entry(dn)

        # Get our configuration
        config = servercore.get_ipa_config()

        # Let us add in some missing attributes
        if user.get('homedirectory') is None:
            user['homedirectory'] = '%s/%s' % (config.get('ipahomesrootdir'), user.get('uid'))
            user['homedirectory'] = user['homedirectory'].replace('//', '/')
            user['homedirectory'] = user['homedirectory'].rstrip('/')
        if user.get('loginshell') is None:
            user['loginshell'] = config.get('ipadefaultloginshell')
        if user.get('gecos') is None:
            user['gecos'] = user['uid']

        # If uidnumber is blank the the FDS dna_plugin will automatically
        # assign the next value. So we don't have to do anything with it.

        group_dn="cn=%s,%s,%s" % (config.get('ipadefaultprimarygroup'), servercore.DefaultGroupContainer, servercore.basedn)
        try:
            default_group = servercore.get_entry_by_dn(group_dn, ['dn','gidNumber'])
            if default_group:
                user['gidnumber'] = default_group.get('gidnumber')
        except errors.NotFound:
            # Fake an LDAP error so we can return something useful to the user
            raise ipalib.NotFound, "The default group for new users, '%s', cannot be found." % config.get('ipadefaultprimarygroup')
        except Exception, e:
            # catch everything else
            raise e

        if user.get('krbprincipalname') is None:
            user['krbprincipalname'] = "%s@%s" % (user.get('uid'), servercore.realm)

        # FIXME. This is a hack so we can request separate First and Last
        # name in the GUI.
        if user.get('cn') is None:
            user['cn'] = "%s %s" % (user.get('givenname'),
                                           user.get('sn'))

        # some required objectclasses
        entry.setValues('objectClass', (config.get('ipauserobjectclasses')))
        # entry.setValues('objectClass', ['top', 'person', 'organizationalPerson', 'inetOrgPerson', 'inetUser', 'posixAccount', 'krbPrincipalAux'])

        # fill in our new entry with everything sent by the user
        for u in user:
            entry.setValues(u, user[u])

        result = servercore.add_entry(entry)
        return result
    def forward(self, *args, **kw):
        result = super(crud.Add, self).forward(*args, **kw)
        if result:
            print "User %s added" % args[0]

api.register(user_add)


class user_del(crud.Del):
    'Delete an existing user.'
    def execute(self, *args, **kw):
        """args[0] = uid of the user to remove

           Delete a user. Not to be confused with inactivate_user. This
           makes the entry go away completely.

           uid is the uid of the user to delete

           The memberOf plugin handles removing the user from any other
           groups.
        """
        uid = args[0]
        if uid == "admin":
            # FIXME: do we still want a "special" user?
            raise SyntaxError("admin required")
#            raise ipaerror.gen_exception(ipaerror.INPUT_ADMIN_REQUIRED)
#        logging.info("IPA: delete_user '%s'" % uid)
        user = servercore.get_user_by_uid(uid, ['dn', 'uid'])
        if not user:
            raise errors.NotFound

        return servercore.delete_entry(user['dn'])
    def forward(self, *args, **kw):
        result = super(crud.Del, self).forward(*args, **kw)
        if result:
            print "User %s removed" % args[0]
api.register(user_del)


class user_mod(crud.Mod):
    'Edit an existing user.'
    def execute(self, *args, **kw):
        uid=args[0]
        result = servercore.get_sub_entry(servercore.basedn, "uid=%s" % uid, ["*"])

        user = kw
        dn = result.get('dn')
        del result['dn']
        entry = ipaldap.Entry((dn, servercore.convert_scalar_values(result)))

        for u in user:
            entry.setValues(u, user[u])

        result = servercore.update_entry(entry.toDict())

        return result
    def forward(self, *args, **kw):
        result = super(crud.Mod, self).forward(*args, **kw)
        if result:
            print "User %s modified" % args[0]
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
    def execute(self, *args, **kw):
        uid=args[0]
        result = servercore.get_user_by_uid(uid, ["*"])
        return result
    def forward(self, *args, **kw):
        try:
            result = super(crud.Get, self).forward(*args, **kw)
            if not result: return
            for a in result:
                print a, ": ", result[a]
        except errors.NotFound:
            print "User %s not found" % args[0]
api.register(user_show)
