# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
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
Test the `ipalib/plugins/service.py` module.
"""

import sys
from xmlrpc_test import XMLRPC_test, assert_attr_equal
from ipalib import api
from ipalib import errors


class test_service(XMLRPC_test):
    """
    Test the `service` plugin.
    """
    principal = u'HTTP/ipatest.%s@%s' % (api.env.domain, api.env.realm)
    hostprincipal = u'host/ipatest.%s@%s' % (api.env.domain, api.env.realm)
    kw = {'krbprincipalname': principal}

    def test_1_service_add(self):
        """
        Test adding a HTTP principal using the `xmlrpc.service_add` method.
        """
        (dn, res) = api.Command['service_add'](**self.kw)
        assert res
        assert_attr_equal(res, 'krbprincipalname', self.principal)
        assert_attr_equal(res, 'objectclass', 'ipaobject')

    def test_2_service_add(self):
        """
        Test adding a host principal using `xmlrpc.service_add`. Host
        services are not allowed.
        """
        kw = {'krbprincipalname': self.hostprincipal}
        try:
            api.Command['service_add'](**kw)
        except errors.HostService:
            pass
        else:
            assert False

    def test_3_service_add(self):
        """
        Test adding a malformed principal ('foo').
        """
        kw = {'krbprincipalname': u'foo'}
        try:
            api.Command['service_add'](**kw)
        except errors.MalformedServicePrincipal:
            pass
        else:
            assert False

    def test_4_service_add(self):
        """
        Test adding a malformed principal ('HTTP/foo@FOO.NET').
        """
        kw = {'krbprincipalname': u'HTTP/foo@FOO.NET'}
        try:
            api.Command['service_add'](**kw)
        except errors.RealmMismatch:
            pass
        else:
            assert False

    def test_5_service_show(self):
        """
        Test the `xmlrpc.service_show` method.
        """
        (dn, res) = api.Command['service_show'](self.principal)
        assert res
        assert_attr_equal(res, 'krbprincipalname', self.principal)

    def test_6_service_find(self):
        """
        Test the `xmlrpc.service_find` method.
        """
        (res, truncated) = api.Command['service_find'](self.principal)
        assert res
        assert_attr_equal(res[0][1], 'krbprincipalname', self.principal)

    def test_7_service_del(self):
        """
        Test the `xmlrpc.service_del` method.
        """
        res = api.Command['service_del'](self.principal)
        assert res == True

        # Verify that it is gone
        try:
            api.Command['service_show'](self.principal)
        except errors.NotFound:
            pass
        else:
            assert False

