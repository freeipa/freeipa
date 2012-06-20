import shlex
import sys
import contextlib
import StringIO

import nose

from tests import util
from ipalib import api, errors
from ipapython.version import API_VERSION


class TestCLIParsing(object):
    """Tests that commandlines are correctly parsed to Command keyword args
    """
    def check_command(self, commandline, expected_command_name, **kw_expected):
        argv = shlex.split(commandline)
        executioner = api.Backend.cli

        cmd = executioner.get_command(argv)
        kw_got = executioner.argv_to_keyword_arguments(cmd, argv[1:])
        util.assert_deepequal(expected_command_name, cmd.name, 'Command name')
        util.assert_deepequal(kw_expected, kw_got)

    def run_command(self, command_name, **kw):
        """Run a command on the server"""
        if not api.Backend.xmlclient.isconnected():
            api.Backend.xmlclient.connect(fallback=False)
        try:
            api.Command[command_name](**kw)
        except errors.NetworkError:
            raise nose.SkipTest('%r: Server not available: %r' %
                                (self.__module__, api.env.xmlrpc_uri))

    @contextlib.contextmanager
    def fake_stdin(self, string_in):
        """Context manager that temporarily replaces stdin to read a string"""
        old_stdin = sys.stdin
        sys.stdin = StringIO.StringIO(string_in)
        yield
        sys.stdin = old_stdin

    def test_ping(self):
        self.check_command('ping', 'ping',
            version=API_VERSION)

    def test_user_show(self):
        self.check_command('user-show admin', 'user_show',
            uid=u'admin',
            rights=False,
            raw=False,
            all=False,
            version=API_VERSION)

    def test_user_show_underscore(self):
        self.check_command('user_show admin', 'user_show',
            uid=u'admin',
            rights=False,
            raw=False,
            all=False,
            version=API_VERSION)

    def test_group_add(self):
        self.check_command('group-add tgroup1 --desc="Test group"',
            'group_add',
            cn=u'tgroup1',
            description=u'Test group',
            nonposix=False,
            external=False,
            raw=False,
            all=False,
            version=API_VERSION)

    def test_sudocmdgroup_add_member(self):
        # Test CSV splitting is done correctly
        self.check_command(
            # The following is as it would appear on the command line:
            r'sudocmdgroup-add-member tcmdgroup1 --sudocmds=abc,\"de,f\",\\,g',
            'sudocmdgroup_add_member',
            cn=u'tcmdgroup1',
            sudocmd=[u'abc', u'de,f', u'\\', u'g'],
            raw=False,
            all=False,
            version=API_VERSION)

    def test_group_add_nonposix(self):
        self.check_command('group-add tgroup1 --desc="Test group" --nonposix',
            'group_add',
            cn=u'tgroup1',
            description=u'Test group',
            nonposix=True,
            external=False,
            raw=False,
            all=False,
            version=API_VERSION)

    def test_group_add_gid(self):
        self.check_command('group-add tgroup1 --desc="Test group" --gid=1234',
            'group_add',
            cn=u'tgroup1',
            description=u'Test group',
            gidnumber=u'1234',
            nonposix=False,
            external=False,
            raw=False,
            all=False,
            version=API_VERSION)

    def test_group_add_interactive(self):
        with self.fake_stdin('Test group\n'):
            self.check_command('group-add tgroup1', 'group_add',
                cn=u'tgroup1',
                description=u'Test group',
                nonposix=False,
                external=False,
                raw=False,
                all=False,
                version=API_VERSION)

    def test_dnsrecord_add(self):
        self.check_command('dnsrecord-add test-example.com ns --a-rec=1.2.3.4',
            'dnsrecord_add',
            dnszoneidnsname=u'test-example.com',
            idnsname=u'ns',
            arecord=[u'1.2.3.4'],
            structured=False,
            force=False,
            raw=False,
            all=False,
            version=API_VERSION)

    def test_dnsrecord_del_all(self):
        try:
            self.run_command('dnszone_add', idnsname=u'test-example.com',
                idnssoamname=u'ns.test-example.com', force=True)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        try:
            self.run_command('dnsrecord_add',
                dnszoneidnsname=u'test-example.com',
                idnsname=u'ns', arecord=u'1.2.3.4')
            with self.fake_stdin('yes\n'):
                self.check_command('dnsrecord_del test-example.com ns',
                    'dnsrecord_del',
                    dnszoneidnsname=u'test-example.com',
                    idnsname=u'ns',
                    del_all=True,
                    structured=False,
                    raw=False,
                    all=False,
                    version=API_VERSION)
            with self.fake_stdin('YeS\n'):
                self.check_command('dnsrecord_del test-example.com ns',
                    'dnsrecord_del',
                    dnszoneidnsname=u'test-example.com',
                    idnsname=u'ns',
                    del_all=True,
                    structured=False,
                    raw=False,
                    all=False,
                    version=API_VERSION)
        finally:
            self.run_command('dnszone_del', idnsname=u'test-example.com')

    def test_dnsrecord_del_one_by_one(self):
        try:
            self.run_command('dnszone_add', idnsname=u'test-example.com',
                idnssoamname=u'ns.test-example.com', force=True)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        try:
            records = (u'1 1 E3B72BA346B90570EED94BE9334E34AA795CED23',
                       u'2 1 FD2693C1EFFC11A8D2BE57229212A04B45663791')
            for record in records:
                self.run_command('dnsrecord_add',
                    dnszoneidnsname=u'test-example.com', idnsname=u'ns',
                    sshfprecord=record)
            with self.fake_stdin('no\nyes\nyes\n'):
                self.check_command('dnsrecord_del test-example.com ns',
                    'dnsrecord_del',
                    dnszoneidnsname=u'test-example.com',
                    idnsname=u'ns',
                    del_all=False,
                    sshfprecord=records,
                    structured=False,
                    raw=False,
                    all=False,
                    version=API_VERSION)
        finally:
            self.run_command('dnszone_del', idnsname=u'test-example.com')

    def test_dnsrecord_add_ask_for_missing_fields(self):
        sshfp_parts = (1, 1, u'E3B72BA346B90570EED94BE9334E34AA795CED23')

        with self.fake_stdin('SSHFP\n%d\n%d\n%s' % sshfp_parts):
            self.check_command('dnsrecord-add test-example.com sshfp',
                'dnsrecord_add',
                dnszoneidnsname=u'test-example.com',
                idnsname=u'sshfp',
                sshfp_part_fp_type=sshfp_parts[0],
                sshfp_part_algorithm=sshfp_parts[1],
                sshfp_part_fingerprint=sshfp_parts[2],
                structured=False,
                raw=False,
                all=False,
                force=False,
                version=API_VERSION)

        # NOTE: when a DNS record part is passed via command line, it is not
        # converted to its base type when transfered via wire
        with self.fake_stdin('%d\n%s' % (sshfp_parts[1], sshfp_parts[2])):
            self.check_command('dnsrecord-add test-example.com sshfp ' \
                    '--sshfp-algorithm=%d' % sshfp_parts[0],
                'dnsrecord_add',
                dnszoneidnsname=u'test-example.com',
                idnsname=u'sshfp',
                sshfp_part_fp_type=sshfp_parts[0],
                sshfp_part_algorithm=unicode(sshfp_parts[1]),   # passed via cmdline
                sshfp_part_fingerprint=sshfp_parts[2],
                structured=False,
                raw=False,
                all=False,
                force=False,
                version=API_VERSION)

        with self.fake_stdin(sshfp_parts[2]):
            self.check_command('dnsrecord-add test-example.com sshfp ' \
                    '--sshfp-algorithm=%d --sshfp-fp-type=%d' % (sshfp_parts[0], sshfp_parts[1]),
                'dnsrecord_add',
                dnszoneidnsname=u'test-example.com',
                idnsname=u'sshfp',
                sshfp_part_fp_type=unicode(sshfp_parts[0]),     # passed via cmdline
                sshfp_part_algorithm=unicode(sshfp_parts[1]),   # passed via cmdline
                sshfp_part_fingerprint=sshfp_parts[2],
                structured=False,
                raw=False,
                all=False,
                force=False,
                version=API_VERSION)
