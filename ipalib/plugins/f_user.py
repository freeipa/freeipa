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


# Command to get the idea how plugins will interact with api.env
class envtest(frontend.Command):
    'Show current environment.'
    def run(*args, **kw):
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
        return 1
api.register(user_add)


class user_del(crud.Del):
    'Delete an existing user.'
api.register(user_del)


class user_mod(crud.Mod):
    'Edit an existing user.'
api.register(user_mod)


class user_find(crud.Find):
    'Search the users.'
#    def execute(self, *args, **kw):
#        uid=args[0]
#        result = servercore.get_sub_entry(servercore.basedn, "uid=%s" % uid, ["*"])
#        return result
api.register(user_find)


class user_show(crud.Get):
    'Examine an existing user.'
api.register(user_show)
