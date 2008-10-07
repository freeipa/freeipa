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
Controller classes.
"""

import simplejson
from ipalib.plugable import ReadOnly, lock


class Controller(ReadOnly):
    exposed = True

    def __init__(self, template=None):
        self.template = template
        lock(self)

    def output_xhtml(self, **kw):
        return self.template.serialize(
            output='xhtml-strict',
            format='pretty',
            **kw
        )

    def output_json(self, **kw):
        return simplejson.dumps(kw, sort_keys=True, indent=4)

    def __call__(self, **kw):
        json = bool(kw.pop('_format', None) == 'json')
        result = self.run(**kw)
        assert type(result) is dict
        if json or self.template is None:
            return self.output_json(**result)
        return self.output_xhtml(**result)

    def run(self, **kw):
        return {}


class Command(Controller):
    def __init__(self, command, template=None):
        self.command = command
        super(Command, self).__init__(template)

    def run(self, **kw):
        return dict(command=self.command)


class Index(Controller):
    def __init__(self, api, template=None):
        self.api = api
        super(Index, self).__init__(template)

    def run(self):
        return dict(api=self.api)
