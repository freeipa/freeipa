# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (c) 2010  Red Hat
# See file 'copying' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the gnu general public license as
# published by the free software foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but without any warranty; without even the implied warranty of
# merchantability or fitness for a particular purpose.  See the
# gnu general public license for more details.
#
# You should have received a copy of the gnu general public license
# along with this program; if not, write to the Free Software
# Foundation, inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""
Plugins not accessible directly through the CLI, commands used internally
"""

import json

from ipalib import api, errors
from ipalib import Command
from ipalib import Str
from ipalib.output import Output
from ipalib.text import _
from ipalib.util import json_serialize

class json_metadata(Command):
    """
    Export plugin meta-data for the webUI.
    """
    INTERNAL = True

    takes_args = (
        Str('objname?',
            doc=_('Name of object to export'),
        ),
    )

    has_output = (
        Output('result', dict, doc=_('Dict of JSON encoded IPA Objects')),
    )

    def execute(self, objname):
        if objname and objname in self.api.Object:
            return dict(
                result=dict(
                    ((objname, json_serialize(self.api.Object[objname])), )
                )
            )
        return dict(
            result=dict(
                (o.name, json_serialize(o)) for o in self.api.Object()
            )
        )

    def output_for_cli(self, textui, result, *args, **options):
        print json.dumps(result, default=json_serialize)

api.register(json_metadata)

