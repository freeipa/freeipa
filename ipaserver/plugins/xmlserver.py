# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
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
Loads WSGI server plugins.
"""

from ipalib import api

if 'in_server' in api.env and api.env.in_server is True:
    from ipaserver.rpcserver import wsgi_dispatch, xmlserver, jsonserver_kerb, jsonserver_session, login_kerberos, login_password, change_password, xmlserver_session
    api.register(wsgi_dispatch)
    api.register(xmlserver)
    api.register(jsonserver_kerb)
    api.register(jsonserver_session)
    api.register(login_kerberos)
    api.register(login_password)
    api.register(change_password)
    api.register(xmlserver_session)
