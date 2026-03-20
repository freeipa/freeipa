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

from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.util import unlock_principal_password

GK_USER1 = 'gkuser1'
GK_USER2 = 'gkuser2'
GK_INIT_PW = 'TempSecret123!'
GK_USER_PW = 'Secret123'

ALL_DEFAULT_ENCTYPES = [
    '(aes256-cts-hmac-sha1-96)',
    '(aes128-cts-hmac-sha1-96)',
    '(camellia128-cts-cmac)',
    '(camellia256-cts-cmac)',
]


@contextmanager
def use_keytab(principal, keytab):
    with private_ccache() as ccache_file:
        old_principal = getattr(context, 'principal', None)
        try:
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


@contextmanager
def kinit_as_user(principal, password):
    """Kinit as *principal* into a private ccache; yield its path.

    private_ccache() already sets KRB5CCNAME in os.environ, so callers
    (and ipautil.run) inherit it automatically.
    """
    with private_ccache() as ccache_path:
        ipautil.run(
            ['kinit', principal],
            stdin=password + '\n',
            raiseonerr=True,
            capture_output=True,
            capture_error=True,
        )
        yield ccache_path


def run_getkeytab(args, env=None, stdin=None):
    """Run ipa-getkeytab with arbitrary arguments."""
    return ipautil.run(
        ['ipa-getkeytab'] + list(args),
        raiseonerr=False,
        capture_output=True,
        capture_error=True,
        stdin=stdin,
        env=env,
    )


def run_rmkeytab(args, env=None):
    """Run ipa-rmkeytab with arbitrary arguments."""
    return ipautil.run(
        ['ipa-rmkeytab'] + list(args),
        raiseonerr=False,
        capture_output=True,
        capture_error=True,
        env=env,
    )


def klist_keytab(keytab_path):
    """Run ``klist -ekt`` and return the result object."""
    return ipautil.run(
        ['klist', '-ekt', keytab_path],
        raiseonerr=False,
        capture_output=True,
        capture_error=True,
    )


@pytest.fixture(scope='class')
def test_host(request):
    host_tracker = host_plugin.HostTracker(u'test-host')
    return host_tracker.make_fixture(request)


@pytest.fixture(scope='class')
def test_service(request, test_host, keytab_retrieval_setup):
    service_tracker = service_plugin.ServiceTracker(u'srv', test_host.name)
    test_host.ensure_exists()
    return service_tracker.make_fixture(request)


@pytest.fixture(scope='class')
def gk_users(request, keytab_retrieval_setup):
    """Create GK_USER1 and GK_USER2; delete them after the class."""
    for uid in (GK_USER1, GK_USER2):
        tracker = UserTracker(
            name=uid, givenname='Test', sn='GKUser',
            userpassword=GK_INIT_PW,
        )
        tracker.make_fixture(request)
        tracker.make_create_command()()
        tracker.exists = True
        unlock_principal_password(uid, GK_INIT_PW, GK_USER_PW)


@pytest.mark.needs_ipaapi
class KeytabRetrievalTest(cmdline_test):
    """
    Base class for keytab retrieval tests
    """
    command = "ipa-getkeytab"
    keytabname = None

    @pytest.fixture(autouse=True, scope="class")
    def keytab_retrieval_setup(self, request, cmdline_setup):
        cls = request.cls
        keytabfd, keytabname = tempfile.mkstemp()

        os.close(keytabfd)
        os.unlink(keytabname)

        cls.keytabname = keytabname

        def fin():
            try:
                os.unlink(cls.keytabname)
            except OSError:
                pass

        request.addfinalizer(fin)

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

    def _get_user1_keytab(self):
        """Populate self.keytabname with GK_USER1's keytab."""
        run_getkeytab(
            ['-s', api.env.host, '-p', GK_USER1, '-k', self.keytabname]
        )

    def _assert_getkeytab_succeeds(self, result):
        """Assert ipa-getkeytab returned success with the expected message."""
        assert result.returncode == 0
        assert (
            'Keytab successfully retrieved and stored in:'
            in result.error_output
        )


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

    @pytest.fixture(autouse=True, scope="class")
    def bindmethods_setup(self, request, keytab_retrieval_setup):
        cls = request.cls
        try:
            cls.dm_password = retrieve_dm_password()
        except errors.NotFound as e:
            pytest.skip(e.args)

        tempfd, temp_ca_cert = tempfile.mkstemp()

        os.close(tempfd)

        shutil.copy(os.path.join(paths.IPA_CA_CRT), temp_ca_cert)

        cls.ca_cert = temp_ca_cert

        def fin():
            try:
                os.unlink(cls.ca_cert)
            except OSError:
                pass
        request.addfinalizer(fin)

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
def test_smb_svc(request, test_host, smb_service_setup):
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
    dm_password = None
    keytabname = None

    @pytest.fixture(autouse=True, scope="class")
    def smb_service_setup(self, request, keytab_retrieval_setup):
        cls = request.cls
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
                assert False,  ('No correct ACI to the allow ipaNTUserAttrs '
                                'for SMB service')

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
                assert False, "No correct ACI to the ipaNTHash for SMB service"
            except errors.EmptyResult:
                assert False, "No arcfour-hmac in Kerberos keys"
            except errors.DatabaseError:
                # Most likely ipaNTHash already existed -- we either get
                # OPERATIONS_ERROR or UNWILLING_TO_PERFORM, both map to
                # the same DatabaseError class.
                assert False, "LDAP Entry corruption after generation"

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


# -----------------------------------------------------------------------
# User-principal tests ported from bash acceptance tests
# (t.ipa-get-rm-keytabs.sh: getkeytab_001 – getkeytab_006)
# -----------------------------------------------------------------------


@pytest.mark.tier1
@pytest.mark.usefixtures('gk_users')
class test_getkeytab_users(KeytabRetrievalTest):
    """
    User-principal ipa-getkeytab tests (bash getkeytab_001 – getkeytab_006).
    """
    command = "ipa-getkeytab"

    def _ensure_keytab_absent(self):
        try:
            os.unlink(self.keytabname)
        except OSError:
            pass

    # --- getkeytab_001: quiet mode, access rights, missing ccache ---

    def test_insufficient_access_as_other_user(self):
        """Retrieving another user's keytab without admin rights fails."""
        principal1 = '{}@{}'.format(GK_USER1, api.env.realm)
        principal2 = '{}@{}'.format(GK_USER2, api.env.realm)
        with kinit_as_user(principal1, GK_USER_PW):
            result = run_getkeytab(
                ['-s', api.env.host,
                 '-p', principal2,
                 '-k', self.keytabname],
            )
        assert result.returncode == 9
        assert (
            'Failed to parse result: Insufficient access rights'
            in result.error_output
        )

    def test_empty_ccache_returns_exit6(self):
        """An empty ccache (simulating kdestroy) returns exit 6."""
        principal1 = '{}@{}'.format(GK_USER1, api.env.realm)
        with private_ccache():
            result = run_getkeytab(
                ['-s', api.env.host, '-p', principal1,
                 '-k', self.keytabname],
            )
        assert result.returncode == 6
        assert (
            'Kerberos User Principal not found. '
            'Do you have a valid Credential Cache?'
            in result.error_output
        )

    def test_quiet_suppresses_success_message(self):
        """-q must suppress the keytab-stored success message.

        Note: test_6_quiet_mode (line 268) checks -q returncode with a
        service principal but does not verify the message is absent.
        """
        result = run_getkeytab(
            ['-q', '-s', api.env.host, '-p', GK_USER1,
             '-k', self.keytabname],
        )
        assert result.returncode == 0
        assert (
            'Keytab successfully retrieved and stored in:'
            not in result.error_output
        )

    # Skipped: test_normal_mode_shows_success_message
    # — covered by test_6_quiet_mode (line 268) which verifies the success
    # message appears without -q.

    # --- getkeytab_002: --server / -s ---

    @pytest.mark.parametrize('flag', ['--server', '-s'])
    def test_invalid_server_fails(self, flag):
        """An invalid server hostname returns exit 9 with bind error."""
        result = run_getkeytab(
            [flag, 'invalid.ipaserver.com',
             '-p', GK_USER1,
             '-k', self.keytabname],
        )
        assert result.returncode == 9
        assert 'Failed to bind to server' in result.error_output

    @pytest.mark.parametrize('flag', ['--server', '-s'])
    def test_valid_server_succeeds(self, flag):
        """A valid server hostname retrieves the keytab successfully.

        Note: -s case is also covered by test_7_server_name_check
        (line 284) with a service principal.
        """
        result = run_getkeytab(
            [flag, api.env.host, '-p', GK_USER1,
             '-k', self.keytabname],
        )
        self._assert_getkeytab_succeeds(result)

    # --- getkeytab_003: --principal / -p ---

    @pytest.mark.parametrize('flag', ['--principal', '-p'])
    @pytest.mark.parametrize('principal', [
        pytest.param('unknownuser', id='unknown'),
        pytest.param(
            '{}@INVALID.IPASERVER.REALM.COM'.format(GK_USER1),
            id='invalid-realm',
        ),
    ])
    def test_principal_not_found(self, flag, principal):
        """Unresolvable principals return exit 9 with not-found error.

        Note: test_1_run (line 218) tests a similar scenario with a
        non-existent service principal.
        """
        result = run_getkeytab(
            ['-s', api.env.host, flag, principal,
             '-k', self.keytabname],
        )
        assert result.returncode == 9
        assert (
            'Failed to parse result: PrincipalName not found.'
            in result.error_output
        )

    @pytest.mark.parametrize('flag', ['--principal', '-p'])
    @pytest.mark.parametrize('with_realm', [False, True],
                             ids=['bare', 'with-realm'])
    def test_valid_principal_succeeds(self, flag, with_realm):
        """Both bare and realm-qualified principals retrieve the keytab."""
        principal = ('{}@{}'.format(GK_USER1, api.env.realm)
                     if with_realm else GK_USER1)
        result = run_getkeytab(
            ['-s', api.env.host, flag, principal,
             '-k', self.keytabname],
        )
        self._assert_getkeytab_succeeds(result)

    # --- getkeytab_004: --keytab / -k ---

    @pytest.mark.parametrize('flag', ['--keytab', '-k'])
    def test_creates_keytab_when_absent(self, flag):
        """The keytab file is created when it does not previously exist."""
        self._ensure_keytab_absent()
        result = run_getkeytab(
            ['-s', api.env.host, '-p', GK_USER1, flag, self.keytabname],
        )
        self._assert_getkeytab_succeeds(result)
        assert os.path.isfile(self.keytabname)

    @pytest.mark.parametrize('flag', ['--keytab', '-k'])
    def test_keytab_contains_aes_enctypes(self, flag):
        """The created keytab contains both aes256 and aes128 entries."""
        run_getkeytab(
            ['-s', api.env.host, '-p', GK_USER1, flag, self.keytabname]
        )
        klist_result = klist_keytab(self.keytabname)
        assert api.env.realm in klist_result.output
        assert 'aes128' in klist_result.output
        assert 'aes256' in klist_result.output

    @pytest.mark.parametrize('flag', ['--keytab', '-k'])
    def test_text_file_path_returns_exit11(self, flag):
        """Writing to a pre-existing plain-text file returns exit 11."""
        txtfd, txt_path = tempfile.mkstemp(suffix='.txt')
        os.close(txtfd)
        try:
            result = run_getkeytab(
                ['-s', api.env.host, '-p', GK_USER1, flag, txt_path],
            )
            assert result.returncode == 11
            assert 'Failed to add key to the keytab' in result.error_output
        finally:
            try:
                os.unlink(txt_path)
            except OSError:
                pass

    # --- getkeytab_005: -e encryption types ---

    def test_system_keytab_has_default_enctypes(self):
        """The system keytab must contain both aes256 and aes128."""
        klist_result = klist_keytab('/etc/krb5.keytab')
        assert '(aes256-cts-hmac-sha1-96)' in klist_result.output
        assert '(aes128-cts-hmac-sha1-96)' in klist_result.output

    @pytest.mark.parametrize('enctype,expected', [
        ('aes256-cts', '(aes256-cts-hmac-sha1-96)'),
        ('aes128-cts', '(aes128-cts-hmac-sha1-96)'),
        ('camellia128-cts-cmac', '(camellia128-cts-cmac)'),
        ('camellia256-cts-cmac', '(camellia256-cts-cmac)'),
    ])
    def test_single_enctype(self, enctype, expected):
        """With -e <enctype> only that enctype appears and kinit works.

        Note: test_8_keytab_encryption_check tests -e with multiple
        enctypes but only asserts success, not klist content.
        """
        self._ensure_keytab_absent()
        run_getkeytab(
            ['-s', api.env.host, '-p', GK_USER1,
             '-k', self.keytabname, '-e', enctype],
        )
        klist_result = klist_keytab(self.keytabname)
        assert expected in klist_result.output
        for enc in ALL_DEFAULT_ENCTYPES:
            if enc != expected:
                assert enc not in klist_result.output
        assert '(des3-cbc-sha1)' not in klist_result.output
        assert '(arcfour-hmac)' not in klist_result.output
        with private_ccache():
            ipautil.run(
                ['kinit', '-k', '-t', self.keytabname,
                 '{}@{}'.format(GK_USER1, api.env.realm)],
                raiseonerr=True,
                capture_output=True,
                capture_error=True,
            )

    def test_invalid_enctype_returns_exit8(self):
        """An invalid -e value returns exit 8 and creates no keytab."""
        self._ensure_keytab_absent()
        result = run_getkeytab(
            ['-s', api.env.host, '-p', GK_USER1,
             '-k', self.keytabname, '-e', 'invalid'],
        )
        assert result.returncode == 8
        assert 'Warning unrecognized encryption type' in result.error_output
        assert not os.path.isfile(self.keytabname)

    # --- getkeytab_006: --password / -P ---

    @pytest.mark.parametrize('flag', ['--password', '-P'])
    def test_password_flag_rotates_keys(self, flag):
        """After --password and a random-key reset, the original password
        will no longer authenticate.

        Sequence: admin sets password-derived keys -> user kinits -> user
        regenerates random keys -> kinit with the original password must fail.
        """
        self._ensure_keytab_absent()
        principal1 = '{}@{}'.format(GK_USER1, api.env.realm)
        stdin = '{pw}\n{pw}\n'.format(pw=GK_USER_PW)
        result = run_getkeytab(
            ['-s', api.env.host, '-p', GK_USER1,
             '-k', self.keytabname, flag],
            stdin=stdin,
        )
        assert result.returncode == 0
        with kinit_as_user(principal1, GK_USER_PW):
            regen = run_getkeytab(
                ['-s', api.env.host, '-p', GK_USER1,
                 '-k', self.keytabname],
            )
            assert regen.returncode == 0
        with private_ccache():
            kinit_result = ipautil.run(
                ['kinit', principal1],
                stdin=GK_USER_PW + '\n',
                raiseonerr=False,
                capture_output=True,
                capture_error=True,
            )
        assert kinit_result.returncode != 0
        assert (
            'Password incorrect' in kinit_result.error_output
            or 'Preauthentication failed' in kinit_result.error_output
        )

    # --- getkeytab_007: -D / -w bind DN error cases ---

    # Skipped: test_no_ccache_returns_exit6
    # — identical to test_empty_ccache_returns_exit6 above.
    # Skipped: test_valid_dm_credentials_succeed
    # — covered by TestBindMethods.test_retrieval_with_dm_creds (line 375).

    @pytest.mark.parametrize('extra_args,exitcode,message', [
        (['-D', ' ', '-w', GK_USER_PW],
         9, 'Anonymous Binds are not allowed'),
        (['-D', 'cn=Directory Manager', '-w', ' '],
         9, 'Simple bind failed'),
        (['-D', 'cn=Directory Manager'],
         10, 'Bind password required when using a bind DN'),
    ], ids=['empty-dn', 'wrong-password', 'missing-password'])
    def test_binddn_error_cases(self, extra_args, exitcode, message):
        """Bind DN error cases return appropriate exit codes."""
        result = run_getkeytab(
            ['--server', 'localhost',
             '-p', GK_USER1,
             '-k', self.keytabname] + extra_args,
        )
        assert result.returncode == exitcode
        assert message in result.error_output


# -----------------------------------------------------------------------
# ipa-rmkeytab tests (bash rmkeytab_001 – rmkeytab_003)
# -----------------------------------------------------------------------


@pytest.mark.tier1
@pytest.mark.usefixtures('gk_users')
class test_rmkeytab_cmd(KeytabRetrievalTest):
    """
    ipa-rmkeytab tests (bash rmkeytab_001 – rmkeytab_003).
    """
    command = "ipa-rmkeytab"

    # --- rmkeytab_001: -p removes a named principal ---

    def test_invalid_principal_returns_exit5(self):
        """A non-existent principal name returns exit 5."""
        self._get_user1_keytab()
        result = run_rmkeytab(['-p', 'invalidprinc', '-k', self.keytabname])
        assert result.returncode == 5
        assert 'principal not found' in result.error_output

    def test_valid_principal_removed(self):
        """A present principal is removed and absent from klist."""
        self._get_user1_keytab()
        result = run_rmkeytab(['-p', GK_USER1, '-k', self.keytabname])
        assert result.returncode == 0
        assert (
            'Removing principal {}'.format(GK_USER1)
            in result.error_output
        )
        assert GK_USER1 not in klist_keytab(self.keytabname).output

    # --- rmkeytab_002: -r removes all principals of the given realm ---

    def test_realm_removes_all_principals(self):
        """All principals of the realm are removed and absent from klist."""
        self._get_user1_keytab()
        result = run_rmkeytab(['-r', api.env.realm, '-k', self.keytabname])
        assert result.returncode == 0
        assert (
            'Removing principal {}@{}'.format(GK_USER1, api.env.realm)
            in result.error_output
        )
        assert api.env.realm not in klist_keytab(self.keytabname).output

    # --- rmkeytab_003: -k with a non-existent path ---

    def test_invalid_keytab_path_returns_exit7(self):
        """A non-existent keytab path returns exit 7."""
        self._get_user1_keytab()
        result = run_rmkeytab(
            ['-p', GK_USER1, '-k', '/opt/invalid.keytab']
        )
        assert result.returncode == 7
        assert 'Failed to set cursor' in result.error_output
