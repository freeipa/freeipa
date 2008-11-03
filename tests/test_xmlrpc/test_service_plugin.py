# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Test the `ipalib/plugins/f_service` module.
"""

import sys
from xmlrpc_test import XMLRPC_test
from ipalib import api
from ipalib import errors
from ipalib.cli import CLI

try:
    api.finalize()
except StandardError:
    pass

class test_Service(XMLRPC_test):
    """
    Test the `f_service` plugin.
    """
    principal='HTTP/ipatest.%s@%s' % (api.env.domain, api.env.realm)
    hostprincipal='host/ipatest.%s@%s' % (api.env.domain, api.env.realm)
    kw={'principal':principal}

    def test_add(self):
        """
        Test adding a HTTP principal using the `xmlrpc.service_add` method.
        """
        res = api.Command['service_add'](**self.kw)
        assert res
        assert res.get('krbprincipalname','') == self.principal

    def test_add_host(self):
        """
        Test adding a host principal using `xmlrpc.service_add` method.
        """
        kw={'principal':self.hostprincipal}
        try:
            res = api.Command['service_add'](**kw)
        except errors.HostService:
            pass
        else:
            assert False

    def test_doshow(self):
        """
        Test the `xmlrpc.service_show` method.
        """
        res = api.Command['service_show'](self.principal)
        assert res
        assert res.get('krbprincipalname','') == self.principal

    def test_find(self):
        """
        Test the `xmlrpc.service_find` method.
        """
        res = api.Command['service_find'](self.principal)
        assert res
        assert len(res) == 2
        assert res[1].get('krbprincipalname','') == self.principal

    def test_remove(self):
        """
        Test the `xmlrpc.service_del` method.
        """
        res = api.Command['service_del'](self.principal)
        assert res == True

        # Verify that it is gone
        try:
            res = api.Command['service_show'](self.principal)
        except errors.NotFound:
            pass
        else:
            assert False
