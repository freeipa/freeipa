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
import tempfile

import gssapi
import pytest

from ipalib import api
from ipapython import ipautil, ipaldap
from ipaserver.plugins.ldap2 import ldap2
from ipatests.test_cmdline.cmdline import cmdline_test
from ipatests.test_xmlrpc.tracker import host_plugin, service_plugin

def use_keytab(principal, keytab):
    try:
        tmpdir = tempfile.mkdtemp(prefix = "tmp-")
        ccache_file = 'FILE:%s/ccache' % tmpdir
        name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        store = {'ccache': ccache_file,
                 'client_keytab': keytab}
        os.environ['KRB5CCNAME'] = ccache_file
        gssapi.Credentials(name=name, usage='initiate', store=store)
        conn = ldap2(api)
        conn.connect(autobind=ipaldap.AUTOBIND_DISABLED)
        conn.disconnect()
    except gssapi.exceptions.GSSError as e:
        raise Exception('Unable to bind to LDAP. Error initializing principal %s in %s: %s' % (principal, keytab, str(e)))
    finally:
        os.environ.pop('KRB5CCNAME', None)
        if tmpdir:
            shutil.rmtree(tmpdir)


@pytest.fixture(scope='class')
def test_host(request):
    host_tracker = host_plugin.HostTracker(u'test-host')
    return host_tracker.make_fixture(request)


@pytest.fixture(scope='class')
def test_service(request, test_host):
    service_tracker = service_plugin.ServiceTracker(u'srv', test_host.name)
    test_host.ensure_exists()
    return service_tracker.make_fixture(request)


@pytest.mark.tier0
class test_ipagetkeytab(cmdline_test):
    """
    Test `ipa-getkeytab`.
    """
    command = "ipa-getkeytab"
    keytabname = None

    @classmethod
    def setup_class(cls):
        super(test_ipagetkeytab, cls).setup_class()

        keytabfd, keytabname = tempfile.mkstemp()

        os.close(keytabfd)
        os.unlink(keytabname)

        cls.keytabname = keytabname

    @classmethod
    def teardown_class(cls):
        super(test_ipagetkeytab, cls).teardown_class()

        try:
            os.unlink(cls.keytabname)
        except OSError:
            pass

    def run_ipagetkeytab(self, service_principal, raiseonerr=False):
        new_args = [self.command,
                    "-s", api.env.host,
                    "-p", service_principal,
                    "-k", self.keytabname]
        return ipautil.run(
            new_args,
            stdin=None,
            raiseonerr=raiseonerr,
            capture_error=True)

    def test_1_run(self, test_service):
        """
        Create a keytab with `ipa-getkeytab` for a non-existent service.
        """
        test_service.ensure_missing()
        result = self.run_ipagetkeytab(test_service.name)
        err = result.error_output

        assert 'Failed to parse result: PrincipalName not found.\n' in err, err
        rc = result.returncode
        assert rc > 0, rc

    def test_2_run(self, test_service):
        """
        Create a keytab with `ipa-getkeytab` for an existing service.
        """
        test_service.ensure_exists()

        result = self.run_ipagetkeytab(test_service.name, raiseonerr=True)
        expected = 'Keytab successfully retrieved and stored in: %s\n' % (
            self.keytabname)
        assert expected in result.error_output, (
            'Success message not in output:\n%s' % result.error_output)

    def test_3_use(self, test_service):
        """
        Try to use the service keytab.
        """
        use_keytab(test_service.name, self.keytabname)

    def test_4_disable(self, test_service):
        """
        Disable a kerberos principal
        """
        retrieve_cmd = test_service.make_retrieve_command()
        result = retrieve_cmd()
        # Verify that it has a principal key
        assert result[u'result'][u'has_keytab']

        # Disable it
        disable_cmd = test_service.make_disable_command()
        disable_cmd()

        # Verify that it looks disabled
        result = retrieve_cmd()
        assert not result[u'result'][u'has_keytab']

    def test_5_use_disabled(self, test_service):
        """
        Try to use the disabled keytab
        """
        try:
            use_keytab(test_service.name, self.keytabname)
        except Exception as errmsg:
            assert('Unable to bind to LDAP. Error initializing principal' in str(errmsg))
