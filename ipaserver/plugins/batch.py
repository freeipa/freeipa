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

import logging

import six

from ipalib import api, errors
from ipalib import Command
from ipalib.frontend import Local
from ipalib.parameters import Str, Dict
from ipalib.output import Output
from ipalib.text import _
from ipalib.request import context
from ipalib.plugable import Registry
from ipapython.version import API_VERSION

__doc__ = _("""
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

""")

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

register = Registry()

@register()
class batch(Command):
    __doc__ = _('Make multiple ipa calls via one remote procedure call')
    NO_CLI = True

    takes_args = (
        Dict('methods*',
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

    def _validate_request(self, request):
        """
        Check that an individual request in a batch is parseable and the
        commands exists.
        """
        if 'method' not in request:
            raise errors.RequirementError(name='method')
        if 'params' not in request:
            raise errors.RequirementError(name='params')
        name = request['method']
        if (name not in self.api.Command or
                isinstance(self.api.Command[name], Local)):
            raise errors.CommandError(name=name)

        # If params are not formated as a tuple(list, dict)
        # the following lines will raise an exception
        # that triggers an internal server error
        # Raise a ConversionError instead to report the issue
        # to the client
        try:
            a, kw = request['params']
            newkw = dict((str(k), v) for k, v in kw.items())
            api.Command[name].args_options_2_params(*a, **newkw)
        except (AttributeError, ValueError, TypeError):
            raise errors.ConversionError(
                name='params',
                error=_(u'must contain a tuple (list, dict)'))
        except Exception as e:
            raise errors.ConversionError(
                name='params',
                error=str(e))

    def _repr_iter(self, **params):
        """
        Iterate through the request and use the Command _repr_intr so
        that sensitive information (passwords) is not exposed.

        In case of a malformatted request redact the entire thing.
        """
        exceptions = False
        for arg in (params.get('methods', [])):
            try:
                self._validate_request(arg)
            except Exception:
                # redact the whole request since we don't know what's in it
                exceptions = True
                yield u'********'
                continue

            name = arg['method']
            a, kw = arg['params']
            newkw = dict((str(k), v) for k, v in kw.items())
            param = api.Command[name].args_options_2_params(
                *a, **newkw)

            yield '{}({})'.format(
                api.Command[name].name,
                ', '.join(api.Command[name]._repr_iter(**param))
            )

        if exceptions:
            logger.debug('batch: %s',
                         ', '.join(super(batch, self)._repr_iter(**params)))

    def execute(self, methods=None, **options):
        results = []
        for arg in (methods or []):
            params = dict()
            name = None
            try:
                self._validate_request(arg)
                name = arg['method']
                a, kw = arg['params']
                newkw = dict((str(k), v) for k, v in kw.items())
                params = api.Command[name].args_options_2_params(
                    *a, **newkw)
                newkw.setdefault('version', options['version'])

                result = api.Command[name](*a, **newkw)
                logger.info(
                    '%s: batch: %s(%s): SUCCESS',
                    getattr(context, 'principal', 'UNKNOWN'),
                    name,
                    ', '.join(api.Command[name]._repr_iter(**params))
                )
                result['error']=None
            except Exception as e:
                if (isinstance(e, errors.RequirementError) or
                        isinstance(e, errors.CommandError) or
                        isinstance(e, errors.ConversionError)):
                    logger.info(
                        '%s: batch: %s',
                        context.principal,  # pylint: disable=no-member
                        e.__class__.__name__
                    )
                else:
                    logger.info(
                        '%s: batch: %s(%s): %s',
                        context.principal, name,  # pylint: disable=no-member
                        ', '.join(api.Command[name]._repr_iter(**params)),
                        e.__class__.__name__
                    )
                if isinstance(e, errors.PublicError):
                    reported_error = e
                else:
                    reported_error = errors.InternalError()
                result = dict(
                    error=reported_error.strerror,
                    error_code=reported_error.errno,
                    error_name=unicode(type(reported_error).__name__),
                    error_kw=reported_error.kw,
                )
            results.append(result)
        return dict(count=len(results) , results=results)
