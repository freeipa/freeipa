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
Package containing server backend.
"""

from xmlrpclib import dumps, Fault
from ipalib import api

try:
    from mod_python import apache
    api.bootstrap(context='server', log=None, debug=True)
    api.finalize()
except ImportError:
    pass


def xmlrpc(req):
    if req.method != 'POST':
        req.allow_methods(['POST'], 1)
        return apache.HTTP_METHOD_NOT_ALLOWED

    if apache.mpm_query(apache.AP_MPMQ_IS_THREADED):
        response = dumps(
            Fault(3, 'Apache must use the forked model'), methodresponse=True
        )
    else:
        response = api.Backend.xmlserver.marshaled_dispatch(req.read(), None)

    req.content_type = 'text/xml'
    req.set_content_length(len(response))
    req.write(response)
    return apache.OK
