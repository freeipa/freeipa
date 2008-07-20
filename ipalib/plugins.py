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

class user(base.Object):
	pass
api.register(user)

class adduser(crud.Add):
	_obj = 'user'
api.register(adduser)

class deluser(crud.Del):
	_obj = 'user'
api.register(deluser)

class moduser(crud.Mod):
	_obj = 'user'
api.register(moduser)

class finduser(crud.Find):
	_obj = 'user'
api.register(finduser)



class group(base.Object):
	pass
api.register(group)

class addgroup(crud.Add):
	_obj = 'group'
api.register(addgroup)

class delgroup(crud.Del):
	_obj = 'group'
api.register(delgroup)

class modgroup(crud.Mod):
	_obj = 'group'
api.register(modgroup)

class findgroup(crud.Find):
	_obj = 'group'
api.register(findgroup)


class service(base.Object):
	pass
api.register(service)

class addservice(crud.Add):
	_obj = 'service'
api.register(addservice)

class delservice(crud.Del):
	_obj = 'service'
api.register(delservice)

class modservice(crud.Mod):
	_obj = 'service'
api.register(modservice)

class findservice(crud.Find):
	_obj = 'service'
api.register(findservice)
