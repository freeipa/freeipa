# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Backend plugin for Kerberos.

This wraps the python-kerberos and python-krbV bindings.
"""

import sys
from ipalib import api
from ipalib.backend import Backend
import krbV

ENCODING = 'UTF-8'


class krb(Backend):
    """
    Kerberos backend plugin.

    This wraps the `krbV` bindings (and will eventually wrap the `kerberos`
    bindings also).  Importantly, this plugin does correct Unicode
    encoding/decoding of values going-to/coming-from the bindings.
    """

    def __default_ccache(self):
        """
        Return the ``krbV.CCache`` for the default credential cache.
        """
        return krbV.default_context().default_ccache()

    def __default_principal(self):
        """
        Return the ``krb5.Principal`` for the default credential cache.
        """
        return self.__default_ccache().principal()

    def __get_ccache(self, ccname):
        """
        Return the ``krbV.CCache`` for the ``ccname`` credential ccache.
        """
        return krbV.CCache(ccname)

    def __get_principal(self, ccname):
        """
        Return the ``krb5.Principal`` for the ``ccname`` credential ccache.
        """
        return self.__get_ccache(ccname).principal()

    def default_ccname(self):
        """
        Return the default ccache file name.

        This will return something like '/tmp/krb5cc_500'.

        This cannot return anything meaningful if used in the server as a
        request is processed.
        """
        return self.__default_ccache().name

    def default_principal(self):
        """
        Return the principal name in default credential cache.

        This will return something like 'admin@EXAMPLE.COM'.  If no credential
        cache exists for the invoking user, None is returned.

        This cannot return anything meaningful if used in the server as a
        request is processed.
        """
        return self.__default_principal().name.decode(ENCODING)

    def default_realm(self):
        """
        Return the realm from the default credential cache.

        This will return something like 'EXAMPLE.COM'.  If no credential cache
        exists for the invoking user, None is returned.

        This cannot return anything meaningful if used in the server as a
        request is processed.
        """
        return krbV.default_context().default_realm.decode(ENCODING)

    def get_principal(self, ccname):
        """
        Return the principal from credential cache file at ``ccname``.

        This will return something like 'admin@EXAMPLE.COM'.
        """
        return self.__get_principal(ccname).name.decode(ENCODING)

    def get_realm(self, ccname):
        """
        Return the realm from credential cache file at ``ccname``.

        This will return something like 'EXAMPLE.COM'.
        """
        return self.__get_principal(ccname).realm.decode(ENCODING)


api.register(krb)
