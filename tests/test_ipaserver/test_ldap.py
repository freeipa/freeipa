# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

# Test some simple LDAP requests using the ldap2 backend

# This fetches a certificate from a host principal so we can ensure that the
# schema is working properly. We know this because the schema will tell the
# encoder not to utf-8 encode binary attributes.

# The DM password needs to be set in ~/.ipa/.dmpw

import nose
import os
from ipaserver.plugins.ldap2 import ldap2
from ipalib.plugins.service import service, service_show
from ipalib.plugins.host import host
import nss.nss as nss
from ipalib import api, x509, create_api, errors
from ipapython import ipautil
from ipapython.dn import DN

class test_ldap(object):
    """
    Test various LDAP client bind methods.
    """

    def setUp(self):
        self.conn = None
        self.ldapuri = 'ldap://%s' % ipautil.format_netloc(api.env.host)
        self.ccache = '/tmp/krb5cc_%d' % os.getuid()
        nss.nss_init_nodb()
        self.dn = DN(('krbprincipalname','ldap/%s@%s' % (api.env.host, api.env.realm)),
                     ('cn','services'),('cn','accounts'),api.env.basedn)

    def tearDown(self):
        if self.conn and self.conn.isconnected():
            self.conn.disconnect()

    def test_anonymous(self):
        """
        Test an anonymous LDAP bind using ldap2
        """
        self.conn = ldap2(shared_instance=False, ldap_uri=self.ldapuri)
        self.conn.connect()
        (dn, entry_attrs) = self.conn.get_entry(self.dn, ['usercertificate'])
        cert = entry_attrs.get('usercertificate')
        cert = cert[0]
        serial = unicode(x509.get_serial_number(cert, x509.DER))
        assert serial is not None

    def test_GSSAPI(self):
        """
        Test a GSSAPI LDAP bind using ldap2
        """
        if not ipautil.file_exists(self.ccache):
            raise nose.SkipTest('Missing ccache %s' % self.ccache)
        self.conn = ldap2(shared_instance=False, ldap_uri=self.ldapuri)
        self.conn.connect(ccache='FILE:%s' % self.ccache)
        (dn, entry_attrs) = self.conn.get_entry(self.dn, ['usercertificate'])
        cert = entry_attrs.get('usercertificate')
        cert = cert[0]
        serial = unicode(x509.get_serial_number(cert, x509.DER))
        assert serial is not None

    def test_simple(self):
        """
        Test a simple LDAP bind using ldap2
        """
        pwfile = api.env.dot_ipa + os.sep + ".dmpw"
        if ipautil.file_exists(pwfile):
            fp = open(pwfile, "r")
            dm_password = fp.read().rstrip()
            fp.close()
        else:
            raise nose.SkipTest("No directory manager password in %s" % pwfile)
        self.conn = ldap2(shared_instance=False, ldap_uri=self.ldapuri)
        self.conn.connect(bind_dn=DN(('cn', 'directory manager')), bind_pw=dm_password)
        (dn, entry_attrs) = self.conn.get_entry(self.dn, ['usercertificate'])
        cert = entry_attrs.get('usercertificate')
        cert = cert[0]
        serial = unicode(x509.get_serial_number(cert, x509.DER))
        assert serial is not None

    def test_Backend(self):
        """
        Test using the ldap2 Backend directly (ala ipa-server-install)
        """

        # Create our own api because the one generated for the tests is
        # a client-only api. Then we register in the commands and objects
        # we need for the test.
        myapi = create_api(mode=None)
        myapi.bootstrap(context='cli', in_server=True, in_tree=True)
        myapi.register(ldap2)
        myapi.register(host)
        myapi.register(service)
        myapi.register(service_show)
        myapi.finalize()

        pwfile = api.env.dot_ipa + os.sep + ".dmpw"
        if ipautil.file_exists(pwfile):
            fp = open(pwfile, "r")
            dm_password = fp.read().rstrip()
            fp.close()
        else:
            raise nose.SkipTest("No directory manager password in %s" % pwfile)
        myapi.Backend.ldap2.connect(bind_dn=DN(('cn', 'Directory Manager')), bind_pw=dm_password)

        result = myapi.Command['service_show']('ldap/%s@%s' %  (api.env.host, api.env.realm,))
        entry_attrs = result['result']
        cert = entry_attrs.get('usercertificate')
        cert = cert[0]
        serial = unicode(x509.get_serial_number(cert, x509.DER))
        assert serial is not None

    def test_autobind(self):
        """
        Test an autobind LDAP bind using ldap2
        """
        ldapuri = 'ldapi://%%2fvar%%2frun%%2fslapd-%s.socket' % api.env.realm.replace('.','-')
        self.conn = ldap2(shared_instance=False, ldap_uri=ldapuri)
        try:
            self.conn.connect(autobind=True)
        except errors.DatabaseError, e:
            if e.desc == 'Inappropriate authentication':
                raise nose.SkipTest("Only executed as root")
        (dn, entry_attrs) = self.conn.get_entry(self.dn, ['usercertificate'])
        cert = entry_attrs.get('usercertificate')
        cert = cert[0]
        serial = unicode(x509.get_serial_number(cert, x509.DER))
        assert serial is not None
