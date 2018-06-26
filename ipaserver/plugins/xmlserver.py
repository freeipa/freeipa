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

from ipalib import Registry, api

register = Registry()


if api.env.context in ('server', 'lite'):
    from ipaserver.rpcserver import (
        wsgi_dispatch, xmlserver, jsonserver_i18n_messages, jsonserver_kerb,
        jsonserver_session, login_kerberos, login_x509, login_password,
        change_password, sync_token, xmlserver_session)
    register()(wsgi_dispatch)
    register()(xmlserver)
    register()(jsonserver_i18n_messages)
    register()(jsonserver_kerb)
    register()(jsonserver_session)
    register()(login_kerberos)
    register()(login_x509)
    register()(login_password)
    register()(change_password)
    register()(sync_token)
    register()(xmlserver_session)
