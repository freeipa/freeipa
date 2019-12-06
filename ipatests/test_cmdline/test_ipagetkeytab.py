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

from __future__ import absolute_import

import os
import shutil
import tempfile

import gssapi
import pytest

from ipapython.ipautil import private_ccache
from ipalib import api, errors
from ipalib.request import context
from ipaplatform.paths import paths
from ipapython import ipautil, ipaldap
from ipaserver.plugins.ldap2 import ldap2
from ipatests.test_cmdline.cmdline import cmdline_test
from ipatests.test_xmlrpc.tracker import host_plugin, service_plugin
from ipatests.test_xmlrpc.xmlrpc_test import fuzzy_digits, add_oc
from contextlib import contextmanager


@contextmanager
def use_keytab(principal, keytab):
    with private_ccache() as ccache_file:
        try:
            old_principal = getattr(context, 'principal', None)
            name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
            store = {'ccache': ccache_file,
                     'client_keytab': keytab}
            gssapi.Credentials(name=name, usage='initiate', store=store)
            conn = ldap2(api)
            conn.connect(ccache=ccache_file,
                         autobind=ipaldap.AUTOBIND_DISABLED)
            yield conn
            conn.disconnect()
        except gssapi.exceptions.GSSError as e:
            raise Exception('Unable to bind to LDAP. Error initializing '
                            'principal %s in %s: %s' % (principal, keytab,
                                                        str(e)))
        finally:
            setattr(context, 'principal', old_principal)


@pytest.fixture(scope='class')
def test_host(request):
    host_tracker = host_plugin.HostTracker(u'test-host')
    return host_tracker.make_fixture(request)


@pytest.fixture(scope='class')
def test_service(request, test_host):
    service_tracker = service_plugin.ServiceTracker(u'srv', test_host.name)
    test_host.ensure_exists()
    return service_tracker.make_fixture(request)


@pytest.mark.needs_ipaapi
class KeytabRetrievalTest(cmdline_test):
    """
    Base class for keytab retrieval tests
    """
    command = "ipa-getkeytab"
    keytabname = None

    @classmethod
    def setup_class(cls):
        super(KeytabRetrievalTest, cls).setup_class()

        keytabfd, keytabname = tempfile.mkstemp()

        os.close(keytabfd)
        os.unlink(keytabname)

        cls.keytabname = keytabname

    @classmethod
    def teardown_class(cls):
        super(KeytabRetrievalTest, cls).teardown_class()

        try:
            os.unlink(cls.keytabname)
        except OSError:
            pass

    def run_ipagetkeytab(self, service_principal, args=tuple(),
                         raiseonerr=False, stdin=None):
        new_args = [self.command,
                    "-p", service_principal,
                    "-k", self.keytabname]

        if not args:
            new_args.extend(['-s', api.env.host])
        else:
            new_args.extend(list(args))

        return ipautil.run(
            new_args,
            stdin=stdin,
            raiseonerr=raiseonerr,
            capture_error=True)

    def assert_success(self, *args, **kwargs):
        result = self.run_ipagetkeytab(*args, **kwargs)
        expected = 'Keytab successfully retrieved and stored in: %s\n' % (
            self.keytabname)
        assert expected in result.error_output, (
            'Success message not in output:\n%s' % result.error_output)

    def assert_failure(self, retcode, message, *args, **kwargs):
        result = self.run_ipagetkeytab(*args, **kwargs)
        err = result.error_output

        assert message in err
        rc = result.returncode
        assert rc == retcode


@pytest.mark.tier0
class test_ipagetkeytab(KeytabRetrievalTest):
    """
    Test `ipa-getkeytab`.
    """
    command = "ipa-getkeytab"
    keytabname = None

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

        self.assert_success(test_service.name, raiseonerr=True)

    def test_3_use(self, test_service):
        """
        Try to use the service keytab.
        """
        with use_keytab(test_service.name, self.keytabname) as conn:
            assert conn.can_read(test_service.dn, 'objectclass') is True
            assert getattr(context, 'principal') == test_service.name

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
            with use_keytab(test_service.name, self.keytabname) as conn:
                assert conn.can_read(test_service.dn, 'objectclass') is True
                assert getattr(context, 'principal') == test_service.name
        except Exception as errmsg:
            assert('Unable to bind to LDAP. Error initializing principal' in str(errmsg))

    def test_6_quiet_mode(self, test_service):
        """
        Try to use quiet mode
        """
        test_service.ensure_exists()
        # getkeytab without quiet mode option enabled
        result = self.run_ipagetkeytab(test_service.name)
        err = result.error_output.split("\n")[0]
        assert err == f"Keytab successfully retrieved and stored in:" \
                      f" {self.keytabname}"
        assert result.returncode == 0

        # getkeytab with quiet mode option enabled
        result1 = self.run_ipagetkeytab(test_service.name, args=tuple("-q"))
        assert result1.returncode == 0

    def test_7_server_name_check(self, test_service):
        """
        Try to use -s for server name
        """
        test_service.ensure_exists()
        self.assert_success(test_service.name, args=["-s", api.env.host])

    def test_8_keytab_encryption_check(self, test_service):
        """
        Try to use -e for different types of encryption check
        """
        encryptes_list = [
            "aes256-cts-hmac-sha1-96",
            "aes128-cts-hmac-sha256-128",
        ]
        self.assert_success(
            test_service.name, args=["-e", ",".join(encryptes_list)]
        )

    def test_dangling_symlink(self, test_service):
        # see https://pagure.io/freeipa/issue/4607
        test_service.ensure_exists()

        fd, symlink_target = tempfile.mkstemp()
        os.close(fd)
        os.unlink(symlink_target)
        # create dangling symlink
        os.symlink(self.keytabname, symlink_target)

        try:
            self.assert_success(test_service.name, raiseonerr=True)
            assert os.path.isfile(symlink_target)
            assert os.path.samefile(self.keytabname, symlink_target)
        finally:
            os.unlink(symlink_target)


def retrieve_dm_password():
    dmpw_file = os.path.join(api.env.dot_ipa, '.dmpw')

    if not os.path.isfile(dmpw_file):
        raise errors.NotFound(reason='{} file required '
                              'for this test'.format(dmpw_file))

    with open(dmpw_file, 'r') as f:
        dm_password = f.read().strip()

    return dm_password


class TestBindMethods(KeytabRetrievalTest):
    """
    Class that tests '-c'/'-H'/'-Y' flags
    """

    dm_password = None
    ca_cert = None

    @classmethod
    def setup_class(cls):
        super(TestBindMethods, cls).setup_class()

        try:
            cls.dm_password = retrieve_dm_password()
        except errors.NotFound as e:
            pytest.skip(e.args)

        tempfd, temp_ca_cert = tempfile.mkstemp()

        os.close(tempfd)

        shutil.copy(os.path.join(paths.IPA_CA_CRT), temp_ca_cert)

        cls.ca_cert = temp_ca_cert

    @classmethod
    def teardown_class(cls):
        super(TestBindMethods, cls).teardown_class()

        try:
            os.unlink(cls.ca_cert)
        except OSError:
            pass

    def check_ldapi(self):
        if not api.env.ldap_uri.startswith('ldapi://'):
            pytest.skip("LDAP URI not pointing to LDAPI socket")

    def test_retrieval_with_dm_creds(self, test_service):
        test_service.ensure_exists()

        self.assert_success(
            test_service.name,
            args=[
                '-D', "cn=Directory Manager",
                '-w', self.dm_password,
                '-s', api.env.host])

    def test_retrieval_using_plain_ldap(self, test_service):
        test_service.ensure_exists()
        ldap_uri = 'ldap://{}'.format(api.env.host)

        self.assert_success(
            test_service.name,
            args=[
                '-D', "cn=Directory Manager",
                '-w', self.dm_password,
                '-H', ldap_uri])

    @pytest.mark.skipif(os.geteuid() != 0,
                        reason="Must have root privileges to run this test")
    def test_retrieval_using_ldapi_external(self, test_service):
        test_service.ensure_exists()
        self.check_ldapi()

        self.assert_success(
            test_service.name,
            args=[
                '-Y',
                'EXTERNAL',
                '-H', api.env.ldap_uri])

    def test_retrieval_using_ldap_gssapi(self, test_service):
        test_service.ensure_exists()
        self.check_ldapi()

        self.assert_success(
            test_service.name,
            args=[
                '-Y',
                'GSSAPI',
                '-H', api.env.ldap_uri])

    def test_retrieval_using_ldaps_ca_cert(self, test_service):
        test_service.ensure_exists()

        self.assert_success(
            test_service.name,
            args=[
                '-D', "cn=Directory Manager",
                '-w', self.dm_password,
                '-H', 'ldaps://{}'.format(api.env.host),
                '--cacert', self.ca_cert])

    def test_ldap_uri_server_raises_error(self, test_service):
        test_service.ensure_exists()

        self.assert_failure(
            2,
            "Cannot specify server and LDAP uri simultaneously",
            test_service.name,
            args=[
                '-H', 'ldaps://{}'.format(api.env.host),
                '-s', api.env.host],
            raiseonerr=False)

    def test_invalid_mech_raises_error(self, test_service):
        test_service.ensure_exists()

        self.assert_failure(
            2,
            "Invalid SASL bind mechanism",
            test_service.name,
            args=[
                '-H', 'ldaps://{}'.format(api.env.host),
                '-Y', 'BOGUS'],
            raiseonerr=False)

    def test_mech_bind_dn_raises_error(self, test_service):
        test_service.ensure_exists()

        self.assert_failure(
            2,
            "Cannot specify both SASL mechanism and bind DN simultaneously",
            test_service.name,
            args=[
                '-D', "cn=Directory Manager",
                '-w', self.dm_password,
                '-H', 'ldaps://{}'.format(api.env.host),
                '-Y', 'EXTERNAL'],
            raiseonerr=False)


class SMBServiceTracker(service_plugin.ServiceTracker):
    def __init__(self, name, host_fqdn, options=None):
        super(SMBServiceTracker, self).__init__(name, host_fqdn,
                                                options=options)
        # Create SMB service principal that has POSIX attributes to allow
        # generating SID and adding proper objectclasses
        self.create_keys |= {u'uidnumber', u'gidnumber'}
        self.options[u'addattr'] = [
            u'objectclass=ipaIDObject', u'uidNumber=-1', u'gidNumber=-1']

    def track_create(self, **options):
        super(SMBServiceTracker, self).track_create(**options)
        self.attrs[u'uidnumber'] = [fuzzy_digits]
        self.attrs[u'gidnumber'] = [fuzzy_digits]
        self.attrs[u'objectclass'].append(u'ipaIDObject')


@pytest.fixture(scope='class')
def test_smb_svc(request, test_host):
    service_tracker = SMBServiceTracker(u'cifs', test_host.name)
    test_host.ensure_exists()
    return service_tracker.make_fixture(request)


@pytest.mark.tier0
@pytest.mark.skipif(u'ipantuserattrs' not in add_oc([], u'ipantuserattrs'),
                    reason="Must have trust support enabled for this test")
class test_smb_service(KeytabRetrievalTest):
    """
    Test `ipa-getkeytab` for retrieving explicit enctypes
    """
    command = "ipa-getkeytab"
    keytabname = None

    @classmethod
    def setup_class(cls):
        super(test_smb_service, cls).setup_class()

        try:
            cls.dm_password = retrieve_dm_password()
        except errors.NotFound as e:
            pytest.skip(e.args)

    def test_create(self, test_smb_svc):
        """
        Create a keytab with `ipa-getkeytab` for an existing service.
        """
        test_smb_svc.ensure_exists()

        # Request a keytab with explicit encryption types
        enctypes = ['aes128-cts-hmac-sha1-96',
                    'aes256-cts-hmac-sha1-96', 'arcfour-hmac']
        args = ['-e', ','.join(enctypes), '-s', api.env.host]
        self.assert_success(test_smb_svc.name, args=args, raiseonerr=True)

    def test_use(self, test_smb_svc):
        """
        Try to use the service keytab to regenerate ipaNTHash value
        """
        # Step 1. Extend objectclass to allow ipaNTHash attribute
        # We cannot verify write access to objectclass
        with use_keytab(test_smb_svc.name, self.keytabname) as conn:
            entry = conn.get_entry(test_smb_svc.dn, ['objectclass'])
            entry['objectclass'].extend(['ipaNTUserAttrs'])
            try:
                conn.update_entry(entry)
            except errors.ACIError:
                assert ('No correct ACI to the allow ipaNTUserAttrs '
                        'for SMB service' in "failure")

        # Step 2. With ipaNTUserAttrs in place, we can ask to regenerate
        # ipaNTHash value. We can also verify it is possible to write to
        # ipaNTHash attribute while being an SMB service
        with use_keytab(test_smb_svc.name, self.keytabname) as conn:
            assert conn.can_write(test_smb_svc.dn, 'ipaNTHash') is True
            entry = conn.get_entry(test_smb_svc.dn, ['ipaNTHash'])
            entry['ipanthash'] = b'MagicRegen'
            try:
                conn.update_entry(entry)
            except errors.ACIError:
                assert ("No correct ACI to the ipaNTHash for SMB service"
                        in "failure")
            except errors.EmptyResult:
                assert "No arcfour-hmac in Kerberos keys" in "failure"
            except errors.DatabaseError:
                # Most likely ipaNTHash already existed -- we either get
                # OPERATIONS_ERROR or UNWILLING_TO_PERFORM, both map to
                # the same DatabaseError class.
                assert "LDAP Entry corruption after generation" in "failure"

        # Update succeeded, now we have either MagicRegen (broken) or
        # a real NT hash in the entry. However, we can only retrieve it as
        # a cn=Directory Manager. When bind_dn is None, ldap2.connect() wil
        # default to cn=Directory Manager.
        conn = ldap2(api)
        conn.connect(bind_dn=None, bind_pw=self.dm_password,
                     autobind=ipaldap.AUTOBIND_DISABLED)
        entry = conn.retrieve(test_smb_svc.dn, ['ipaNTHash'])
        ipanthash = entry.single_value.get('ipanthash')
        conn.disconnect()
        assert ipanthash != b'MagicRegen', 'LDBM backend entry corruption'
