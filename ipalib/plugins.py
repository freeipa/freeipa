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

import crud
import base
from run import api


# Register some methods for the 'user' object:
class user__add(crud.Add):
	pass
api.register(user__add)

class user__del(crud.Del):
	pass
api.register(user__del)

class user__mod(crud.Mod):
	pass
api.register(user__mod)

class user__find(crud.Find):
	pass
api.register(user__find)


# Register some properties for the 'user' object:
class user__firstname(base.Property):
	pass
api.register(user__firstname)

class user__lastname(base.Property):
	pass
api.register(user__lastname)

class user__lastname(base.Property):
	pass
api.register(user__lastname)


# Register some methods for the 'group' object:
class group__add(crud.Add):
	pass
api.register(group__add)

class group__del(crud.Del):
	pass
api.register(group__del)

class group__mod(crud.Mod):
	pass
api.register(group__mod)

class group__find(crud.Find):
	pass
api.register(group__find)


# Register some methods for the 'service' object
class service__add(crud.Add):
	pass
api.register(service__add)

class service__del(crud.Del):
	pass
api.register(service__del)

class service__mod(crud.Mod):
	pass
api.register(service__mod)

class service__find(crud.Find):
	pass
api.register(service__find)


# And to emphasis that the registration order doesn't matter,
# we'll register the objects last:
class group(base.Object):
	pass
api.register(group)

class service(base.Object):
	pass
api.register(service)

class user(base.Object):
	pass
api.register(user)
