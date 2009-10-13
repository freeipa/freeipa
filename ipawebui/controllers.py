# Authors: Jason Gerard DeRose <jderose@redhat.com>
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
Controllers.
"""

from wehjit import util
import json


class JSON(object):
    def __init__(self, url, api):
        self.url = url
        self.api = api

    def __repr__(self):
        return '%s(url=%r)' % (self.__class__.__name__, self.url)

    def __call__(self, env, start):
        util.extract_query(env)
        start('200 OK', [('Content-Type', 'text/plain')])
        for key in sorted(env):
            yield '%s = %r\n' % (key, env[key])


class Command(object):
    def __init__(self, url, cmd, api):
        self.url = url
        self.cmd = cmd
        self.api = api

    def __repr__(self):
        return '%s(url=%r)' % (self.__class__.__name__, self.url)

    def __call__(self, env, start):
        kw = util.extract_query(env)
        ccname = env['KRB5CCNAME']
        self.api.Backend.xmlserver.create_context(ccname)
        result = self.api.Backend.xmlserver.execute(self.cmd.name, **kw)
        start('200 OK', [('Content-Type', 'text/plain')])
        return [
            json.dumps(result, sort_keys=True, indent=4)
        ]
