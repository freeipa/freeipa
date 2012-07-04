# Authors:
#   Adam Young <ayoung@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (c) 2010  Red Hat
# See file 'copying' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Plugin to make multiple ipa calls via one remote procedure call

To run this code in the lite-server

curl   -H "Content-Type:application/json"          -H "Accept:application/json" -H "Accept-Language:en"        --negotiate -u :          --cacert /etc/ipa/ca.crt           -d  @batch_request.json -X POST       http://localhost:8888/ipa/json

where the contents of the file batch_request.json follow the below example

{"method":"batch","params":[[
        {"method":"group_find","params":[[],{}]},
        {"method":"user_find","params":[[],{"whoami":"true","all":"true"}]},
        {"method":"user_show","params":[["admin"],{"all":true}]}
        ],{}],"id":1}

The format of the response is nested the same way.  At the top you will see
  "error": null,
    "id": 1,
    "result": {
        "count": 3,
            "results": [


And then a nested response for each IPA command method sent in the request

"""

from ipalib import api, errors
from ipalib import Command
from ipalib.parameters import Str, Any
from ipalib.output import Output
from ipalib import output
from ipalib.text import _
from ipalib.request import context
from ipapython.version import API_VERSION

class batch(Command):
    NO_CLI = True

    takes_args = (
        Any('methods*',
            doc=_('Nested Methods to execute'),
        ),
    )

    take_options = (
        Str('version',
            cli_name='version',
            doc=_('Client version. Used to determine if server will accept request.'),
            exclude='webui',
            flags=['no_option', 'no_output'],
            default=API_VERSION,
            autofill=True,
        ),
    )

    has_output = (
        Output('count', int, doc=''),
        Output('results', (list, tuple), doc='')
    )

    def execute(self, *args, **options):
        results = []
        for arg in args[0]:
            params = dict()
            name = None
            try:
                if 'method' not in arg:
                    raise errors.RequirementError(name='method')
                if 'params' not in arg:
                    raise errors.RequirementError(name='params')
                name = arg['method']
                if name not in self.Command:
                    raise errors.CommandError(name=name)
                a, kw = arg['params']
                newkw = dict((str(k), v) for k, v in kw.iteritems())
                params = api.Command[name].args_options_2_params(*a, **newkw)

                result = api.Command[name](*a, **newkw)
                self.info(
                    '%s: batch: %s(%s): SUCCESS', context.principal, name, ', '.join(api.Command[name]._repr_iter(**params))
                )
                result['error']=None
            except Exception, e:
                if isinstance(e, errors.RequirementError) or \
                    isinstance(e, errors.CommandError):
                    self.info(
                        '%s: batch: %s', context.principal, e.__class__.__name__
                    )
                else:
                    self.info(
                        '%s: batch: %s(%s): %s', context.principal, name, ', '.join(api.Command[name]._repr_iter(**params)),  e.__class__.__name__
                    )
                if isinstance(e, errors.PublicError):
                    reported_error = e
                else:
                    reported_error = errors.InternalError()
                result = dict(
                    error=reported_error.strerror,
                    error_code=reported_error.errno,
                    error_name=unicode(type(reported_error).__name__),
                )
            results.append(result)
        return dict(count=len(results) , results=results)

api.register(batch)
