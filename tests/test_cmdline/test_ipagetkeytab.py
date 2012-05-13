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
"""
Test `ipa-getkeytab`
"""

import os
import shutil
from cmdline import cmdline_test
from ipalib import api
from ipalib import errors
import tempfile
from ipapython import ipautil
import nose
import tempfile
import krbV
from ipaserver.plugins.ldap2 import ldap2
from ipapython.dn import DN

def use_keytab(principal, keytab):
    try:
        tmpdir = tempfile.mkdtemp(prefix = "tmp-")
        ccache_file = 'FILE:%s/ccache' % tmpdir
        krbcontext = krbV.default_context()
        principal = str(principal)
        keytab = krbV.Keytab(name=keytab, context=krbcontext)
        principal = krbV.Principal(name=principal, context=krbcontext)
        os.environ['KRB5CCNAME'] = ccache_file
        ccache = krbV.CCache(name=ccache_file, context=krbcontext, primary_principal=principal)
        ccache.init(principal)
        ccache.init_creds_keytab(keytab=keytab, principal=principal)
        conn = ldap2(shared_instance=False, ldap_uri=api.env.ldap_uri, base_dn=api.env.basedn)
        conn.connect(ccache=ccache.name)
        conn.disconnect()
    except krbV.Krb5Error, e:
        raise StandardError('Unable to bind to LDAP. Error initializing principal %s in %s: %s' % (principal.name, keytab, str(e)))
    finally:
        del os.environ['KRB5CCNAME']
        if tmpdir:
            shutil.rmtree(tmpdir)

class test_ipagetkeytab(cmdline_test):
    """
    Test `ipa-getkeytab`.
    """
    command = "ipa-client/ipa-getkeytab"
    host_fqdn = u'ipatest.%s' % api.env.domain
    service_princ = u'test/%s@%s' % (host_fqdn, api.env.realm)
    [keytabfd, keytabname] = tempfile.mkstemp()
    os.close(keytabfd)

    def test_0_setup(self):
        """
        Create a host to test against.
        """
        # Create the service
        try:
            api.Command['host_add'](self.host_fqdn, force=True)
        except errors.DuplicateEntry:
            # it already exists, no problem
            pass

    def test_1_run(self):
        """
        Create a keytab with `ipa-getkeytab` for a non-existent service.
        """
        new_args = [self.command,
                    "-s", api.env.host,
                    "-p", "test/notfound.example.com",
                    "-k", self.keytabname,
                   ]
        (out, err, rc) = ipautil.run(new_args, stdin=None, raiseonerr=False)
        assert err == 'Operation failed! PrincipalName not found.\n\n'

    def test_2_run(self):
        """
        Create a keytab with `ipa-getkeytab` for an existing service.
        """
        # Create the service
        try:
            api.Command['service_add'](self.service_princ, force=True)
        except errors.DuplicateEntry:
            # it already exists, no problem
            pass

        os.unlink(self.keytabname)
        new_args = [self.command,
                    "-s", api.env.host,
                    "-p", self.service_princ,
                    "-k", self.keytabname,
                   ]
        try:
            (out, err, rc) = ipautil.run(new_args, None)
            assert err == 'Keytab successfully retrieved and stored in: %s\n' % self.keytabname
        except ipautil.CalledProcessError, e:
            assert (False)

    def test_3_use(self):
        """
        Try to use the service keytab.
        """
        use_keytab(self.service_princ, self.keytabname)

    def test_4_disable(self):
        """
        Disable a kerberos principal
        """
        # Verify that it has a principal key
        entry = api.Command['service_show'](self.service_princ)['result']
        assert(entry['has_keytab'] == True)

        # Disable it
        api.Command['service_disable'](self.service_princ)

        # Verify that it looks disabled
        entry = api.Command['service_show'](self.service_princ)['result']
        assert(entry['has_keytab'] == False)

    def test_5_use_disabled(self):
        """
        Try to use the disabled keytab
        """
        try:
            use_keytab(self.service_princ, self.keytabname)
        except StandardError, errmsg:
            assert('Unable to bind to LDAP. Error initializing principal' in str(errmsg))

    def test_9_cleanup(self):
        """
        Clean up test data
        """
        # First create the host that will use this policy
        os.unlink(self.keytabname)
        api.Command['host_del'](self.host_fqdn)
