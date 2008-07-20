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
Base classes for objects with CRUD functionality.
"""

import base

class add(base.Command):
		pass


class get(base.Command):
		pass


class edit(base.Command):
		pass


class delete(base.Command):
		pass


class find(base.Command):
		pass


class CrudLike(base.Object):
	def get_commands(self):
		return [
			add,
			get,
			edit,
			delete,
			find,
		]
