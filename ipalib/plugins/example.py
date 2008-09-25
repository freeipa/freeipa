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
Some example plugins.
"""


from ipalib import frontend
from ipalib.frontend import Param
from ipalib import api


# Hypothetical functional commands (not associated with any object):
class krbtest(frontend.Command):
    'Test your Kerberos ticket.'
api.register(krbtest)

class discover(frontend.Command):
    'Discover IPA servers on network.'
api.register(discover)


# Register some methods for the 'user' object:
class user_add(frontend.Method):
    'Add a new user.'
api.register(user_add)

class user_del(frontend.Method):
    'Delete an existing user.'
api.register(user_del)

class user_mod(frontend.Method):
    'Edit an existing user.'
api.register(user_mod)

class user_find(frontend.Method):
    'Search the users.'
api.register(user_find)


# Register some properties for the 'user' object:
#class user_givenname(frontend.Property):
#    'User first name'
#    required = True
#api.register(user_givenname)

#class user_sn(frontend.Property):
#    'User last name'
#    required = True
#api.register(user_sn)

#class user_login(frontend.Property):
#    'User login'
#    required = True
#    default_from = frontend.DefaultFrom(
#        lambda first, last: (first[0] + last).lower(),
#        'givenname', 'sn'
#    )
#api.register(user_login)

#class user_initials(frontend.Property):
#    'User initials'
#    required = True
#    default_from = frontend.DefaultFrom(
#        lambda first, last: first[0] + last[0],
#        'givenname', 'sn'
#    )
#api.register(user_initials)


# Register some methods for the 'group' object:
class group_add(frontend.Method):
    'Add a new group.'
api.register(group_add)

class group_del(frontend.Method):
    'Delete an existing group.'
api.register(group_del)

class group_mod(frontend.Method):
    'Edit an existing group.'
api.register(group_mod)

class group_find(frontend.Method):
    'Search the groups.'
api.register(group_find)


# Register some methods for the 'service' object
class service_add(frontend.Method):
    'Add a new service.'
api.register(service_add)

class service_del(frontend.Method):
    'Delete an existing service.'
api.register(service_del)

class service_mod(frontend.Method):
    'Edit an existing service.'
api.register(service_mod)

class service_find(frontend.Method):
    'Search the services.'
api.register(service_find)


# And to emphasis that the registration order doesn't matter,
# we'll register the objects last:
class group(frontend.Object):
    'Group object'
api.register(group)

class service(frontend.Object):
    'Service object'
api.register(service)

class user(frontend.Object):
    'User object'
    takes_params = (
        'givenname',
        'sn',
        'uid',
        'krbprincipalname',
    )
api.register(user)
