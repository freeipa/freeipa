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

import public
from run import api


# Hypothetical functional commands (not associated with any object):
class krbtest(public.cmd):
    def get_doc(self, _):
        return _('test your Kerberos ticket')
api.register(krbtest)

class discover(public.cmd):
    def get_doc(self, _):
        return _('discover IPA servers on network')
api.register(discover)


# Register some methods for the 'user' object:
class user_add(public.mthd):
    def get_doc(self, _):
        return _('add new user')
api.register(user_add)

class user_del(public.mthd):
    def get_doc(self, _):
        return _('delete existing user')
api.register(user_del)

class user_mod(public.mthd):
    def get_doc(self, _):
        return _('edit existing user')
api.register(user_mod)

class user_find(public.mthd):
    def get_doc(self, _):
        return _('search for users')
api.register(user_find)


# Register some properties for the 'user' object:
class user_givenname(public.prop):
    def get_doc(self, _):
        return _('user first name')
api.register(user_givenname)

class user_sn(public.prop):
    def get_doc(self, _):
        return _('user last name')
api.register(user_sn)

class user_login(public.prop):
    def get_doc(self, _):
        return _('user login')
api.register(user_login)


# Register some methods for the 'group' object:
class group_add(public.mthd):
    def get_doc(self, _):
        return _('add new group')
api.register(group_add)

class group_del(public.mthd):
    def get_doc(self, _):
        return _('delete existing group')
api.register(group_del)

class group_mod(public.mthd):
    def get_doc(self, _):
        return _('edit existing group')
api.register(group_mod)

class group_find(public.mthd):
    def get_doc(self, _):
        return _('search for groups')
api.register(group_find)


# Register some methods for the 'service' object
class service_add(public.mthd):
    def get_doc(self, _):
        return _('add new service')
api.register(service_add)

class service_del(public.mthd):
    def get_doc(self, _):
        return _('delete existing service')
api.register(service_del)

class service_mod(public.mthd):
    def get_doc(self, _):
        return _('edit existing service')
api.register(service_mod)

class service_find(public.mthd):
    def get_doc(self, _):
        return _('search for services')
api.register(service_find)


# And to emphasis that the registration order doesn't matter,
# we'll register the objects last:
class group(public.obj):
    def get_doc(self, _):
        return _('')
api.register(group)

class service(public.obj):
    def get_doc(self, _):
        return _('')
api.register(service)

class user(public.obj):
    def get_doc(self, _):
        return _('')
api.register(user)
