#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
"""Misc test for 'ipa' CLI regressions
"""
from __future__ import absolute_import

import base64
import re
import os
import logging
import random
import ssl
from itertools import chain, repeat
import textwrap
import time
import paramiko
import pytest

from cryptography.hazmat.backends import default_backend
from cryptography import x509

from ipalib.constants import IPAAPI_USER

from ipaplatform.paths import paths

from ipapython.dn import DN

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.tasks import tasks as platform_tasks
from ipatests.create_external_ca import ExternalCA
from ipatests.test_ipalib.test_x509 import good_pkcs7, badcert

logger = logging.getLogger(__name__)

# from ipaserver.masters
CONFIGURED_SERVICE = u'configuredService'
ENABLED_SERVICE = u'enabledService'
HIDDEN_SERVICE = u'hiddenService'


class TestIPACommand(IntegrationTest):
    """
    A lot of commands can be executed against a single IPA installation
    so provide a generic class to execute one-off commands that need to be
    tested without having to fire up a full server to run one command.
    """
    topology = 'line'

    def get_cert_base64(self, host, path):
        """Retrieve cert and return content as single line, base64 encoded
        """
        cacrt = host.get_file_contents(path, encoding='ascii')
        cader = ssl.PEM_cert_to_DER_cert(cacrt)
        return base64.b64encode(cader).decode('ascii')

    def test_certmap_match_issue7520(self):
        # https://pagure.io/freeipa/issue/7520
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ['ipa', 'certmap-match', paths.IPA_CA_CRT],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert not result.stderr_text
        assert "0 users matched" in result.stdout_text

        cab64 = self.get_cert_base64(self.master, paths.IPA_CA_CRT)
        result = self.master.run_command(
            ['ipa', 'certmap-match', '--certificate', cab64],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert not result.stderr_text
        assert "0 users matched" in result.stdout_text

    def test_cert_find_issue7520(self):
        # https://pagure.io/freeipa/issue/7520
        tasks.kinit_admin(self.master)
        subject = 'CN=Certificate Authority,O={}'.format(
            self.master.domain.realm)

        # by cert file
        result = self.master.run_command(
            ['ipa', 'cert-find', '--file', paths.IPA_CA_CRT]
        )
        assert subject in result.stdout_text
        assert '1 certificate matched' in result.stdout_text

        # by base64 cert
        cab64 = self.get_cert_base64(self.master, paths.IPA_CA_CRT)
        result = self.master.run_command(
            ['ipa', 'cert-find', '--certificate', cab64]
        )
        assert subject in result.stdout_text
        assert '1 certificate matched' in result.stdout_text

    def test_add_permission_failure_issue5923(self):
        # https://pagure.io/freeipa/issue/5923
        # error response used to contain bytes instead of text

        tasks.kinit_admin(self.master)
        # neither privilege nor permission exists
        result = self.master.run_command(
            ["ipa", "privilege-add-permission", "loc",
             "--permission='System: Show IPA Locations"],
            raiseonerr=False
        )
        assert result.returncode == 2
        err = result.stderr_text.strip()  # pylint: disable=no-member
        assert err == "ipa: ERROR: loc: privilege not found"
        # add privilege
        result = self.master.run_command(
            ["ipa", "privilege-add", "loc"],
        )
        assert 'Added privilege "loc"' in result.stdout_text
        # permission is still missing
        result = self.master.run_command(
            ["ipa", "privilege-add-permission", "loc",
             "--permission='System: Show IPA Locations"],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert "Number of permissions added 0" in result.stdout_text

    def test_change_sysaccount_password_issue7561(self):
        sysuser = 'system'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'

        master = self.master

        base_dn = str(master.domain.basedn)  # pylint: disable=no-member
        entry_ldif = textwrap.dedent("""
            dn: uid=system,cn=sysaccounts,cn=etc,{base_dn}
            changetype: add
            objectclass: account
            objectclass: simplesecurityobject
            uid: system
            userPassword: {original_passwd}
            passwordExpirationTime: 20380119031407Z
            nsIdleTimeout: 0
        """).format(
            base_dn=base_dn,
            original_passwd=original_passwd)
        tasks.ldapmodify_dm(master, entry_ldif)

        tasks.ldappasswd_sysaccount_change(sysuser, original_passwd,
                                           new_passwd, master)

    def get_krbinfo(self, user):
        base_dn = str(self.master.domain.basedn)  # pylint: disable=no-member
        result = tasks.ldapsearch_dm(
            self.master,
            'uid={user},cn=users,cn=accounts,{base_dn}'.format(
                user=user, base_dn=base_dn),
            ['krblastpwdchange', 'krbpasswordexpiration'],
            scope='base'
        )
        output = result.stdout_text.lower()

        # extract krblastpwdchange and krbpasswordexpiration
        krbchg_pattern = 'krblastpwdchange: (.+)\n'
        krbexp_pattern = 'krbpasswordexpiration: (.+)\n'
        krblastpwdchange = re.findall(krbchg_pattern, output)[0]
        krbexp = re.findall(krbexp_pattern, output)[0]
        return krblastpwdchange, krbexp

    def test_ldapmodify_password_issue7601(self):
        user = 'ipauser'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'
        new_passwd2 = 'mynewPwd123'
        master = self.master
        base_dn = str(master.domain.basedn)  # pylint: disable=no-member

        # Create a user with a password
        tasks.kinit_admin(master)
        add_password_stdin_text = "{pwd}\n{pwd}".format(pwd=original_passwd)
        master.run_command(['ipa', 'user-add', user,
                            '--first', user,
                            '--last', user,
                            '--password'],
                           stdin_text=add_password_stdin_text)
        # kinit as that user in order to modify the pwd
        user_kinit_stdin_text = "{old}\n%{new}\n%{new}\n".format(
            old=original_passwd,
            new=original_passwd)
        master.run_command(['kinit', user], stdin_text=user_kinit_stdin_text)
        # Retrieve krblastpwdchange and krbpasswordexpiration
        krblastpwdchange, krbexp = self.get_krbinfo(user)

        # sleep 1 sec (krblastpwdchange and krbpasswordexpiration have at most
        # a 1s precision)
        time.sleep(1)
        # perform ldapmodify on userpassword as dir mgr
        entry_ldif = textwrap.dedent("""
            dn: uid={user},cn=users,cn=accounts,{base_dn}
            changetype: modify
            replace: userpassword
            userpassword: {new_passwd}
        """).format(
            user=user,
            base_dn=base_dn,
            new_passwd=new_passwd)
        tasks.ldapmodify_dm(master, entry_ldif)

        # Test new password with kinit
        master.run_command(['kinit', user], stdin_text=new_passwd)

        # both should have changed
        newkrblastpwdchange, newkrbexp = self.get_krbinfo(user)
        assert newkrblastpwdchange != krblastpwdchange
        assert newkrbexp != krbexp

        # Now test passwd modif with ldappasswd
        time.sleep(1)
        master.run_command([
            paths.LDAPPASSWD,
            '-D', str(master.config.dirman_dn),   # pylint: disable=no-member
            '-w', master.config.dirman_password,
            '-a', new_passwd,
            '-s', new_passwd2,
            '-x', '-ZZ',
            '-H', 'ldap://{hostname}'.format(hostname=master.hostname),
            'uid={user},cn=users,cn=accounts,{base_dn}'.format(
                user=user, base_dn=base_dn)]
        )
        # Test new password with kinit
        master.run_command(['kinit', user], stdin_text=new_passwd2)

        # both should have changed
        newkrblastpwdchange2, newkrbexp2 = self.get_krbinfo(user)
        assert newkrblastpwdchange != newkrblastpwdchange2
        assert newkrbexp != newkrbexp2

    def test_change_selinuxusermaporder(self):
        """
        An update file meant to ensure a more sane default was
        overriding any customization done to the order.
        """
        maporder = "unconfined_u:s0-s0:c0.c1023"

        # set a new default
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["ipa", "config-mod",
             "--ipaselinuxusermaporder={}".format(maporder)],
            raiseonerr=False
        )
        assert result.returncode == 0

        # apply the update
        result = self.master.run_command(
            ["ipa-server-upgrade"],
            raiseonerr=False
        )
        assert result.returncode == 0

        # ensure result is the same
        result = self.master.run_command(
            ["ipa", "config-show"],
            raiseonerr=False
        )
        assert result.returncode == 0
        assert "SELinux user map order: {}".format(
            maporder) in result.stdout_text

    def test_ipa_console(self):
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["ipa", "console"],
            stdin_text="api.env"
        )
        assert "ipalib.config.Env" in result.stdout_text

        filename = tasks.upload_temp_contents(
            self.master,
            "print(api.env)\n"
        )
        result = self.master.run_command(
            ["ipa", "console", filename],
        )
        assert "ipalib.config.Env" in result.stdout_text

    def test_list_help_topics(self):
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["ipa", "help", "topics"],
            raiseonerr=False
        )
        assert result.returncode == 0

    def test_ssh_key_connection(self, tmpdir):
        """
        Integration test for https://pagure.io/SSSD/sssd/issue/3747
        """

        test_user = 'test-ssh'
        external_master_hostname = \
            self.master.external_hostname  # pylint: disable=no-member

        pub_keys = []

        for i in range(40):
            ssh_key_pair = tasks.generate_ssh_keypair()
            pub_keys.append(ssh_key_pair[1])
            with open(os.path.join(
                    tmpdir, 'ssh_priv_{}'.format(i)), 'w') as fp:
                fp.write(ssh_key_pair[0])

        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'user-add', test_user,
                                 '--first=tester', '--last=tester'])

        keys_opts = ' '.join(['--ssh "{}"'.format(k) for k in pub_keys])
        cmd = 'ipa user-mod {} {}'.format(test_user, keys_opts)
        self.master.run_command(cmd)

        # connect with first SSH key
        first_priv_key_path = os.path.join(tmpdir, 'ssh_priv_1')
        # change private key permission to comply with SS rules
        os.chmod(first_priv_key_path, 0o600)

        sshcon = paramiko.SSHClient()
        sshcon.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # first connection attempt is a workaround for
        # https://pagure.io/SSSD/sssd/issue/3669
        try:
            sshcon.connect(external_master_hostname, username=test_user,
                           key_filename=first_priv_key_path, timeout=1)
        except (paramiko.AuthenticationException, paramiko.SSHException):
            pass

        try:
            sshcon.connect(external_master_hostname, username=test_user,
                           key_filename=first_priv_key_path, timeout=1)
        except (paramiko.AuthenticationException,
                paramiko.SSHException) as e:
            pytest.fail('Authentication using SSH key not successful', e)

        journal_cmd = ['journalctl', '--since=today', '-u', 'sshd']
        result = self.master.run_command(journal_cmd)
        output = result.stdout_text
        assert not re.search('exited on signal 13', output)

        # cleanup
        self.master.run_command(['ipa', 'user-del', test_user])

    def test_ssh_leak(self):
        """
        Integration test for https://pagure.io/SSSD/sssd/issue/3794
        """

        def count_pipes():

            res = self.master.run_command(['pidof', 'sssd_ssh'])
            pid = res.stdout_text.strip()
            proc_path = '/proc/{}/fd'.format(pid)
            res = self.master.run_command(['ls', '-la', proc_path])
            fds_text = res.stdout_text.strip()
            return sum((1 for _ in re.finditer(r'pipe', fds_text)))

        test_user = 'test-ssh'

        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'user-add', test_user,
                                 '--first=tester', '--last=tester'])

        certs = []

        # we are ok with whatever certificate for this test
        external_ca = ExternalCA()
        for _dummy in range(3):
            cert = external_ca.create_ca()
            cert = tasks.strip_cert_header(cert.decode('utf-8'))
            certs.append('"{}"'.format(cert))

        cert_args = list(
            chain.from_iterable(list(zip(repeat('--certificate'), certs))))
        cmd = 'ipa user-add-cert {} {}'.format(test_user, ' '.join(cert_args))
        self.master.run_command(cmd)

        tasks.clear_sssd_cache(self.master)

        num_of_pipes = count_pipes()

        for _dummy in range(3):
            self.master.run_command([paths.SSS_SSH_AUTHORIZEDKEYS, test_user])
            current_num_of_pipes = count_pipes()
            assert current_num_of_pipes == num_of_pipes

        # cleanup
        self.master.run_command(['ipa', 'user-del', test_user])

    def test_certificate_out_write_to_file(self):
        # commands to test; name of temporary file will be appended
        commands = [
            ['ipa', 'cert-show', '1', '--certificate-out'],
            ['ipa', 'cert-show', '1', '--chain', '--certificate-out'],
            ['ipa', 'ca-show', 'ipa', '--certificate-out'],
            ['ipa', 'ca-show', 'ipa', '--chain', '--certificate-out'],
        ]

        for command in commands:
            cmd = self.master.run_command(['mktemp'])
            filename = cmd.stdout_text.strip()

            self.master.run_command(command + [filename])

            # Check that a PEM file was written.  If --chain was
            # used, load_pem_x509_certificate will return the
            # first certificate, which is fine for this test.
            data = self.master.get_file_contents(filename)
            x509.load_pem_x509_certificate(data, backend=default_backend())

            self.master.run_command(['rm', '-f', filename])

    def test_sssd_ifp_access_ipaapi(self):
        # check that ipaapi is allowed to access sssd-ifp for smartcard auth
        # https://pagure.io/freeipa/issue/7751
        username = 'admin'
        # get UID for user
        result = self.master.run_command(['ipa', 'user-show', username])
        mo = re.search(r'UID: (\d+)', result.stdout_text)
        assert mo is not None, result.stdout_text
        uid = mo.group(1)

        cmd = [
            'dbus-send',
            '--print-reply', '--system',
            '--dest=org.freedesktop.sssd.infopipe',
            '/org/freedesktop/sssd/infopipe/Users',
            'org.freedesktop.sssd.infopipe.Users.FindByName',
            'string:{}'.format(username)
        ]
        # test IFP as root
        result = self.master.run_command(cmd)
        assert uid in result.stdout_text

        # test IFP as ipaapi
        result = self.master.run_command(
            ['sudo', '-u', IPAAPI_USER, '--'] + cmd
        )
        assert uid in result.stdout_text

    def test_ipa_cacert_manage_install(self):
        # Re-install the IPA CA
        self.master.run_command([
            paths.IPA_CACERT_MANAGE,
            'install',
            paths.IPA_CA_CRT])

        # Test a non-existent file
        result = self.master.run_command([
            paths.IPA_CACERT_MANAGE,
            'install',
            '/var/run/cert_not_found'], raiseonerr=False)
        assert result.returncode == 1

        cmd = self.master.run_command(['mktemp'])
        filename = cmd.stdout_text.strip()

        for contents in (good_pkcs7,):
            self.master.put_file_contents(filename, contents)
            result = self.master.run_command([
                paths.IPA_CACERT_MANAGE,
                'install',
                filename])

        for contents in (badcert,):
            self.master.put_file_contents(filename, contents)
            result = self.master.run_command([
                paths.IPA_CACERT_MANAGE,
                'install',
                filename], raiseonerr=False)
            assert result.returncode == 1

        self.master.run_command(['rm', '-f', filename])

    def test_hbac_systemd_user(self):
        # https://pagure.io/freeipa/issue/7831
        tasks.kinit_admin(self.master)
        # check for presence
        self.master.run_command(
            ['ipa', 'hbacsvc-show', 'systemd-user']
        )
        result = self.master.run_command(
            ['ipa', 'hbacrule-show', 'allow_systemd-user', '--all']
        )
        lines = set(l.strip() for l in result.stdout_text.split('\n'))
        assert 'User category: all' in lines
        assert 'Host category: all' in lines
        assert 'Enabled: TRUE' in lines
        assert 'Services: systemd-user' in lines
        assert 'accessruletype: allow' in lines

        # delete both
        self.master.run_command(
            ['ipa', 'hbacrule-del', 'allow_systemd-user']
        )
        self.master.run_command(
            ['ipa', 'hbacsvc-del', 'systemd-user']
        )

        # run upgrade
        result = self.master.run_command(['ipa-server-upgrade'])
        assert 'Created hbacsvc systemd-user' in result.stderr_text
        assert 'Created hbac rule allow_systemd-user' in result.stderr_text

        # check for presence
        result = self.master.run_command(
            ['ipa', 'hbacrule-show', 'allow_systemd-user', '--all']
        )
        lines = set(l.strip() for l in result.stdout_text.split('\n'))
        assert 'User category: all' in lines
        assert 'Host category: all' in lines
        assert 'Enabled: TRUE' in lines
        assert 'Services: systemd-user' in lines
        assert 'accessruletype: allow' in lines

        self.master.run_command(
            ['ipa', 'hbacsvc-show', 'systemd-user']
        )

        # only delete rule
        self.master.run_command(
            ['ipa', 'hbacrule-del', 'allow_systemd-user']
        )

        # run upgrade
        result = self.master.run_command(['ipa-server-upgrade'])
        assert (
            'hbac service systemd-user already exists' in result.stderr_text
        )
        assert (
            'Created hbac rule allow_systemd-user' not in result.stderr_text
        )
        result = self.master.run_command(
            ['ipa', 'hbacrule-show', 'allow_systemd-user'],
            raiseonerr=False
        )
        assert result.returncode != 0
        assert 'HBAC rule not found' in result.stderr_text

    def test_config_show_configured_services(self):
        # https://pagure.io/freeipa/issue/7929
        states = {CONFIGURED_SERVICE, ENABLED_SERVICE, HIDDEN_SERVICE}
        dn = DN(
            ('cn', 'HTTP'), ('cn', self.master.hostname), ('cn', 'masters'),
            ('cn', 'ipa'), ('cn', 'etc'),
            self.master.domain.basedn  # pylint: disable=no-member
        )

        conn = self.master.ldap_connect()
        entry = conn.get_entry(dn)  # pylint: disable=no-member

        # original setting and all settings without state
        orig_cfg = list(entry['ipaConfigString'])
        other_cfg = [item for item in orig_cfg if item not in states]

        try:
            # test with hidden
            cfg = [HIDDEN_SERVICE]
            cfg.extend(other_cfg)
            entry['ipaConfigString'] = cfg
            conn.update_entry(entry)  # pylint: disable=no-member
            self.master.run_command(['ipa', 'config-show'])

            # test with configured
            cfg = [CONFIGURED_SERVICE]
            cfg.extend(other_cfg)
            entry['ipaConfigString'] = cfg
            conn.update_entry(entry)  # pylint: disable=no-member
            self.master.run_command(['ipa', 'config-show'])
        finally:
            # reset
            entry['ipaConfigString'] = orig_cfg
            conn.update_entry(entry)  # pylint: disable=no-member

    def test_ssh_from_controller(self):
        """https://pagure.io/SSSD/sssd/issue/3979
        Test ssh from test controller after adding
        ldap_deref_threshold=0 to sssd.conf on master

        Steps:
        1. setup a master
        2. add ldap_deref_threshold=0 to sssd.conf on master
        3. add an ipa user
        4. ssh from controller to master using the user created in step 3
        """
        sssd_version = ''
        cmd_output = self.master.run_command(['sssd', '--version'])
        sssd_version = platform_tasks.\
            parse_ipa_version(cmd_output.stdout_text.strip())
        if sssd_version.version < '2.2.0':
            pytest.xfail(reason="sssd 2.2.0 unavailable in F29 nightly")

        username = "testuser" + str(random.randint(200000, 9999999))
        # add ldap_deref_threshold=0 to /etc/sssd/sssd.conf
        domain = self.master.domain
        tasks.modify_sssd_conf(
            self.master,
            domain.name,
            {
                'ldap_deref_threshold': 0
            },
        )
        try:
            self.master.run_command(['systemctl', 'restart', 'sssd.service'])

            # kinit admin
            tasks.kinit_admin(self.master)

            # add ipa user
            cmd = ['ipa', 'user-add',
                   '--first', username,
                   '--last', username,
                   '--password', username]
            input_passwd = 'Secret123\nSecret123\n'
            cmd_output = self.master.run_command(cmd, stdin_text=input_passwd)
            assert 'Added user "%s"' % username in cmd_output.stdout_text
            input_passwd = 'Secret123\nSecret123\nSecret123\n'
            self.master.run_command(['kinit', username],
                                    stdin_text=input_passwd)

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.master.hostname,
                           username=username,
                           password='Secret123')
            client.close()
        finally:
            # revert back to original ldap config
            # remove ldap_deref_threshold=0
            tasks.modify_sssd_conf(
                self.master,
                domain.name,
                {
                    'ldap_deref_threshold': None
                },
            )
            self.master.run_command(['systemctl', 'restart', 'sssd.service'])

    def test_user_mod_change_capitalization_issue5879(self):
        """
        Test that an existing user which has been modified using ipa user-mod
        and has the first and last name beginning with caps does not
        throw the error 'ipa: ERROR: Type or value exists:' and
        instead gets modified

        This is a test case for Pagure issue
        https://pagure.io/freeipa/issue/5879

        Steps:
        1. setup a master
        2. add ipa user on master
        3. now run ipa user-mod and specifying capital letters in names
        4. user details should be modified
        5. ipa: ERROR: Type or value exists is not displayed on console.
        """
        # Create an ipa-user
        tasks.kinit_admin(self.master)
        ipauser = 'ipauser1'
        first = 'ipauser'
        modfirst = 'IpaUser'
        last = 'test'
        modlast = 'Test'
        password = 'Secret123'
        self.master.run_command(
            ['ipa', 'user-add', ipauser, '--first', first, '--last', last,
             '--password'],
            stdin_text="%s\n%s\n" % (password, password))
        cmd = self.master.run_command(
            ['ipa', 'user-mod', ipauser, '--first', modfirst,
             '--last', modlast])
        assert 'Modified user "%s"' % (ipauser) in cmd.stdout_text
        assert 'First name: %s' % (modfirst) in cmd.stdout_text
        assert 'Last name: %s' % (modlast) in cmd.stdout_text
