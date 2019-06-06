import contextlib
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

import six
from six import StringIO

from ipatests import util
from ipatests.test_ipalib.test_x509 import goodcert_headers
from ipalib import api, errors
import pytest

if six.PY3:
    unicode = str

TEST_ZONE = u'zoneadd.%(domain)s' % api.env

HERE = os.path.abspath(os.path.dirname(__file__))
BASE_DIR = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))


@pytest.mark.tier0
@pytest.mark.needs_ipaapi
class TestCLIParsing(object):
    """Tests that commandlines are correctly parsed to Command keyword args
    """
    def check_command(self, commandline, expected_command_name, **kw_expected):
        argv = shlex.split(commandline)
        executioner = api.Backend.cli

        cmd = executioner.get_command(argv)
        kw_got = executioner.parse(cmd, argv[1:])
        kw_got = executioner.process_keyword_arguments(cmd, kw_got)
        util.assert_deepequal(expected_command_name, cmd.name, 'Command name')
        util.assert_deepequal(kw_expected, kw_got)

    def run_command(self, command_name, **kw):
        """Run a command on the server"""
        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()
        try:
            api.Command[command_name](**kw)
        except errors.NetworkError:
            raise unittest.SkipTest('%r: Server not available: %r' %
                                (self.__module__, api.env.xmlrpc_uri))

    @contextlib.contextmanager
    def fake_stdin(self, string_in):
        """Context manager that temporarily replaces stdin to read a string"""
        old_stdin = sys.stdin
        sys.stdin = StringIO(string_in)
        yield
        sys.stdin = old_stdin

    def test_ping(self):
        self.check_command('ping', 'ping')

    def test_plugins(self):
        self.check_command('plugins', 'plugins')

    def test_user_show(self):
        self.check_command('user-show admin', 'user_show', uid=u'admin')

    def test_user_show_underscore(self):
        self.check_command('user_show admin', 'user_show', uid=u'admin')

    def test_group_add(self):
        self.check_command(
            'group-add tgroup1 --desc="Test group"',
            'group_add',
            cn=u'tgroup1',
            description=u'Test group',
        )

    def test_sudocmdgroup_add_member(self):
        # Test CSV splitting is not done
        self.check_command(
            # The following is as it would appear on the command line:
            r'sudocmdgroup-add-member tcmdgroup1 --sudocmds=ab,c --sudocmds=d',
            'sudocmdgroup_add_member',
            cn=u'tcmdgroup1',
            sudocmd=[u'ab,c', u'd'],
        )

    def test_group_add_nonposix(self):
        self.check_command(
            'group-add tgroup1 --desc="Test group" --nonposix',
            'group_add',
            cn=u'tgroup1',
            description=u'Test group',
            nonposix=True,
        )

    def test_group_add_gid(self):
        self.check_command(
            'group-add tgroup1 --desc="Test group" --gid=1234',
            'group_add',
            cn=u'tgroup1',
            description=u'Test group',
            gidnumber=u'1234',
        )

    def test_group_add_interactive(self):
        with self.fake_stdin('Test group\n'):
            self.check_command(
                'group-add tgroup1', 'group_add',
                cn=u'tgroup1',
            )

    def test_dnsrecord_add(self):
        self.check_command(
            'dnsrecord-add %s ns --a-rec=1.2.3.4' % TEST_ZONE,
            'dnsrecord_add',
            dnszoneidnsname=TEST_ZONE,
            idnsname=u'ns',
            arecord=u'1.2.3.4',
        )

    def test_dnsrecord_del_all(self):
        try:
            self.run_command('dnszone_add', idnsname=TEST_ZONE)
        except errors.NotFound:
            raise unittest.SkipTest('DNS is not configured')
        try:
            self.run_command('dnsrecord_add',
                dnszoneidnsname=TEST_ZONE,
                idnsname=u'ns', arecord=u'1.2.3.4', force=True)
            with self.fake_stdin('yes\n'):
                self.check_command(
                    'dnsrecord_del %s ns' % TEST_ZONE,
                    'dnsrecord_del',
                    dnszoneidnsname=TEST_ZONE,
                    idnsname=u'ns',
                    del_all=True,
                )
            with self.fake_stdin('YeS\n'):
                self.check_command(
                    'dnsrecord_del %s ns' % TEST_ZONE,
                    'dnsrecord_del',
                    dnszoneidnsname=TEST_ZONE,
                    idnsname=u'ns',
                    del_all=True,
                )
        finally:
            self.run_command('dnszone_del', idnsname=TEST_ZONE)

    def test_dnsrecord_del_one_by_one(self):
        try:
            self.run_command('dnszone_add', idnsname=TEST_ZONE)
        except errors.NotFound:
            raise unittest.SkipTest('DNS is not configured')
        try:
            records = (u'1 1 E3B72BA346B90570EED94BE9334E34AA795CED23',
                       u'2 1 FD2693C1EFFC11A8D2BE57229212A04B45663791')
            for record in records:
                self.run_command('dnsrecord_add',
                    dnszoneidnsname=TEST_ZONE, idnsname=u'ns',
                    sshfprecord=record)
            with self.fake_stdin('no\nyes\nyes\n'):
                self.check_command(
                    'dnsrecord_del %s ns' % TEST_ZONE,
                    'dnsrecord_del',
                    dnszoneidnsname=TEST_ZONE,
                    idnsname=u'ns',
                    sshfprecord=records,
                )
        finally:
            self.run_command('dnszone_del', idnsname=TEST_ZONE)

    def test_dnsrecord_add_ask_for_missing_fields(self):
        sshfp_parts = (1, 1, u'E3B72BA346B90570EED94BE9334E34AA795CED23')

        with self.fake_stdin('SSHFP\n%d\n%d\n%s' % sshfp_parts):
            self.check_command(
                'dnsrecord-add %s sshfp' % TEST_ZONE,
                'dnsrecord_add',
                dnszoneidnsname=TEST_ZONE,
                idnsname=u'sshfp',
                sshfp_part_fp_type=sshfp_parts[0],
                sshfp_part_algorithm=sshfp_parts[1],
                sshfp_part_fingerprint=sshfp_parts[2],
            )

        # test with lowercase record type
        with self.fake_stdin('sshfp\n%d\n%d\n%s' % sshfp_parts):
            self.check_command(
                'dnsrecord-add %s sshfp' % TEST_ZONE,
                'dnsrecord_add',
                dnszoneidnsname=TEST_ZONE,
                idnsname=u'sshfp',
                sshfp_part_fp_type=sshfp_parts[0],
                sshfp_part_algorithm=sshfp_parts[1],
                sshfp_part_fingerprint=sshfp_parts[2],
            )

        # NOTE: when a DNS record part is passed via command line, it is not
        # converted to its base type when transfered via wire
        with self.fake_stdin('%d\n%s' % (sshfp_parts[1], sshfp_parts[2])):
            self.check_command(
                'dnsrecord-add %s sshfp --sshfp-algorithm=%d' % (
                    TEST_ZONE, sshfp_parts[0]),
                'dnsrecord_add',
                dnszoneidnsname=TEST_ZONE,
                idnsname=u'sshfp',
                sshfp_part_fp_type=sshfp_parts[0],
                # passed via cmdline
                sshfp_part_algorithm=unicode(sshfp_parts[1]),
                sshfp_part_fingerprint=sshfp_parts[2],
            )

        with self.fake_stdin(sshfp_parts[2]):
            self.check_command(
                'dnsrecord-add %s sshfp --sshfp-algorithm=%d '
                '--sshfp-fp-type=%d' % (
                    TEST_ZONE, sshfp_parts[0], sshfp_parts[1]),
                'dnsrecord_add',
                dnszoneidnsname=TEST_ZONE,
                idnsname=u'sshfp',
                # passed via cmdline
                sshfp_part_fp_type=unicode(sshfp_parts[0]),
                # passed via cmdline
                sshfp_part_algorithm=unicode(sshfp_parts[1]),
                sshfp_part_fingerprint=sshfp_parts[2],
            )

    def test_dnsrecord_del_comma(self):
        try:
            self.run_command(
                'dnszone_add', idnsname=TEST_ZONE)
        except errors.NotFound:
            raise unittest.SkipTest('DNS is not configured')
        try:
            self.run_command(
                'dnsrecord_add',
                dnszoneidnsname=TEST_ZONE,
                idnsname=u'test',
                txtrecord=u'"A pretty little problem," said Holmes.')
            with self.fake_stdin('no\nyes\n'):
                self.check_command(
                    'dnsrecord_del %s test' % TEST_ZONE,
                    'dnsrecord_del',
                    dnszoneidnsname=TEST_ZONE,
                    idnsname=u'test',
                    txtrecord=[u'"A pretty little problem," said Holmes.'])
        finally:
            self.run_command('dnszone_del', idnsname=TEST_ZONE)

    def test_idrange_add(self):
        """
        Test idrange-add with interative prompt
        """
        def test_with_interactive_input():
            with self.fake_stdin('5\n500000\n'):
                self.check_command(
                    'idrange_add range1 --base-id=1 --range-size=1',
                    'idrange_add',
                    cn=u'range1',
                    ipabaseid=u'1',
                    ipaidrangesize=u'1',
                    ipabaserid=5,
                    ipasecondarybaserid=500000,
                )

        def test_with_command_line_options():
            self.check_command(
                'idrange_add range1 --base-id=1 --range-size=1 '
                '--rid-base=5 --secondary-rid-base=500000',
                'idrange_add',
                cn=u'range1',
                ipabaseid=u'1',
                ipaidrangesize=u'1',
                ipabaserid=u'5',
                ipasecondarybaserid=u'500000',
            )

        def test_without_options():
            self.check_command(
                'idrange_add range1 --base-id=1 --range-size=1',
                'idrange_add',
                cn=u'range1',
                ipabaseid=u'1',
                ipaidrangesize=u'1',
            )

        adtrust_dn = 'cn=ADTRUST,cn=%s,cn=masters,cn=ipa,cn=etc,%s' % \
                     (api.env.host, api.env.basedn)
        adtrust_is_enabled = api.Command['adtrust_is_enabled']()['result']
        mockldap = None

        if not adtrust_is_enabled:
            # ipa-adtrust-install not run - no need to pass rid-base
            # and secondary-rid-base
            test_without_options()

            # Create a mock service object to test against
            adtrust_add = dict(
                ipaconfigstring=b'enabledService',
                objectclass=[b'top', b'nsContainer', b'ipaConfigObject']
            )

            mockldap = util.MockLDAP()
            mockldap.add_entry(adtrust_dn, adtrust_add)

        # Pass rid-base and secondary-rid-base interactively
        test_with_interactive_input()

        # Pass rid-base and secondary-rid-base on the command-line
        test_with_command_line_options()

        if not adtrust_is_enabled:
            mockldap.del_entry(adtrust_dn)

    def test_certfind(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(goodcert_headers)
            f.flush()
            self.check_command(
                'cert_find --file={}'.format(f.name),
                'cert_find',
                file=goodcert_headers
            )


def test_cli_fsencoding():
    # https://pagure.io/freeipa/issue/5887
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(('LC_', 'LANG'))
    }
    env['LC_ALL'] = 'C'
    env['PYTHONPATH'] = BASE_DIR
    # override confdir so test always fails and does not depend on an
    # existing installation.
    env['IPA_CONFDIR'] = '/'
    p = subprocess.Popen(
        [sys.executable, '-m', 'ipaclient', 'help'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    out, err = p.communicate()

    assert p.returncode != 0, (out, err)
    if sys.version_info >= (3, 7):
        # Python 3.7+ has PEP 538: Legacy C Locale Coercion
        assert b'IPA client is not configured' in err, (out, err)
    else:
        # Python 3.6 does not support UTF-8 fs encoding with non-UTF LC
        assert b'System encoding must be UTF-8' in err, (out, err)


IPA_NOT_CONFIGURED = b'IPA is not configured on this system'
IPA_CLIENT_NOT_CONFIGURED = b'IPA client is not configured on this system'


@pytest.mark.needs_ipaapi
@pytest.mark.skipif(
    os.geteuid() != 0 or os.path.isfile('/etc/ipa/default.conf'),
    reason="Must have root privileges to run this test "
           "and IPA must not be installed")
@pytest.mark.parametrize(
    "args, retcode, output, error",
    [
        # Commands delivered by the client pkg
        (['ipa'], 1, None, IPA_CLIENT_NOT_CONFIGURED),
        (['ipa-certupdate'], 2, None, IPA_CLIENT_NOT_CONFIGURED),
        (['ipa-client-automount'], 2, IPA_CLIENT_NOT_CONFIGURED, None),
        # Commands delivered by the server pkg
        (['ipa-adtrust-install'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-advise'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-backup'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-cacert-manage'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-ca-install'], 1, None,
         b'IPA server is not configured on this system'),
        (['ipa-compat-manage'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-crlgen-manage'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-csreplica-manage'], 1, None, IPA_NOT_CONFIGURED),
        (['ipactl', 'status'], 4, None, b'IPA is not configured'),
        (['ipa-dns-install'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-kra-install'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-ldap-updater',
          '/usr/share/ipa/updates/05-pre_upgrade_plugins.update'],
         2, None, IPA_NOT_CONFIGURED),
        (['ipa-managed-entries'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-nis-manage'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-pkinit-manage'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-replica-manage', 'list'], 1, IPA_NOT_CONFIGURED, None),
        (['ipa-server-certinstall'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-server-upgrade'], 2, None, IPA_NOT_CONFIGURED),
        (['ipa-winsync-migrate'], 1, None, IPA_NOT_CONFIGURED)
    ])
def test_command_ipa_not_installed(args, retcode, output, error):
    """
    Test that the commands properly return that IPA client|server is not
    configured on this system.
    Launch the command specified in args.
    Check that the exit code is as expected and that stdout and stderr
    contain the expected strings.
    """
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    assert retcode == p.returncode
    if output:
        assert output in out
    if error:
        assert error in err
