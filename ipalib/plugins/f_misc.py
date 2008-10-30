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
Misc frontend plugins.
"""

from ipalib import api, Command, Param, Bool


class env_and_context(Command):
    """
    Base class for `env` and `context` commands.
    """

    def run(self, **kw):
        if kw.get('server', False) and not self.api.env.in_server:
            return self.forward()
        return self.execute()

    def output_for_cli(self, ret):
        for (key, value) in ret:
            print '%s = %r' % (key, value)


class env(env_and_context):
    """Show environment variables"""

    takes_options = (
        Param('server?', type=Bool(), default=False,
            doc='Show environment variables of server',
        ),
    )

    def execute(self):
        return tuple(
            (key, self.api.env[key]) for key in self.api.env
        )

api.register(env)


class context(env_and_context):
    """Show request context"""

    takes_options = (
        Param('server?', type=Bool(), default=False,
            doc='Show request context in server',
        ),
    )

    def execute(self):
        return [
            (key, self.api.context[key]) for key in self.api.Context
        ]

api.register(context)
