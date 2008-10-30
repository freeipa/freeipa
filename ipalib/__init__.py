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
Package containing core library.

To learn about the ``ipalib`` library, you should read the code in this order:

    1. Get the big picture from some actual plugins, like `plugins.f_user`.

    2. Learn about the base classes for frontend plugins in `frontend`.

    3. Learn about the core plugin framework in `plugable`.
"""

import plugable
from backend import Backend, Context
from frontend import Command, Object, Method, Property, Application
from ipa_types import Bool, Int, Unicode, Enum
from frontend import Param, DefaultFrom

def get_standard_api():
    return plugable.API(
        Command, Object, Method, Property, Application,
        Backend, Context,
    )


api = get_standard_api()
