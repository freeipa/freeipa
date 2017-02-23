#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import
import six

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

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

register = Registry()


@register()
class batch(Command):
    NO_CLI = True

    takes_args = (
        parameters.Any(
            'methods',
            required=False,
            multivalue=True,
            doc=_(u'Nested Methods to execute'),
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'count',
            int,
        ),
        output.Output(
            'results',
            (list, tuple),
        ),
    )
