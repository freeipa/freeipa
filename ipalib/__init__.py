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
The IPA Library.

To learn about the ``ipalib`` library, you should read the code in this order:

    1. Learn about the plugin framework in `ipalib.plugable`

    2. Learn about the frontend plugins in `ipalib.frontend`

    3. Learn about the backend plugins in `ipalib.backend`

    4. Look at some example plugins in `ipalib.plugins.example`

Here is a short console example on using the plugable API:

>>> from ipalib import api
>>> list(api.register) # Plugins must subclass from one of these base classes:
['Command', 'Method', 'Object', 'Property']
>>> 'user_add' in api.register.Command # Has 'user_add' been registered?
False
>>> import ipalib.load_plugins # This causes all plugins to be loaded
>>> 'user_add' in api.register.Command # Yes, 'user_add' has been registered:
True
>>> list(api) # API is empty till finalize() is called:
[]
>>> api.finalize() # Instantiates plugins, builds API namespaces:
>>> list(api) # Lists the namespaces in the API:
['Command', 'Method', 'Object', 'Property']
>>> 'user_add' in api.Command # Yes, the 'user_add' command exists:
True
>>> api['Command'] is api.Command # Access as dict item or as attribute:
True
>>> list(api.Command) # List available commands:
['discover', 'group_add', 'group_del', 'group_find', 'group_mod', 'krbtest', 'service_add', 'service_del', 'service_find', 'service_mod', 'user_add', 'user_del', 'user_find', 'user_mod']
>>> list(api.Command.user_add) # List public methods for user_add:
['__call__', 'default', 'execute', 'get_doc', 'normalize', 'options', 'validate']
"""

import plugable
import frontend
import backend
import config

api = plugable.API(
    frontend.Command,
    frontend.Object,
    frontend.Method,
    frontend.Property,
    frontend.Application,
    backend.Backend,
)
