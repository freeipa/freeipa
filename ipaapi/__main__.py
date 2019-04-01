from __future__ import absolute_import, print_function

import inspect
import sys

from ipaapi import get_api

api = get_api()

print(dict(api.env))
print(len(api.Command), dir(api.Command))
print(api.Command.__doc__)
print(api.Command.ping.__doc__)
print(api.Command.ping)
if sys.version_info > (3, 5):  # pylint: disable=no-member
    print(inspect.signature(api.Command.cert_find))
    print(inspect.signature(api.Command.dnsrecord_add))

with api:
    print(api.Command.ping())
    print(api.Command.user_show(u"admin"))

with get_api() as api:
    print(api.Command.ping())
