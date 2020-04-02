#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""OTP token tests
"""
from __future__ import absolute_import
import base64
import logging
import paramiko
import pytest
import re
import time
import textwrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.twofactor.totp import TOTP

from ipatests.test_integration.base import IntegrationTest
from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.tasks import tasks as platform_tasks
from six.moves.urllib import parse  # pylint: disable=import-error
# urlparse module has been renamed in Python 3.x
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

PASSWORD = "DummyPassword123"
USER = "opttestuser"
ARMOR = "/tmp/armor"
logger = logging.getLogger(__name__)


def add_otptoken(host, owner, otptype="hotp", digits=6, algo="sha1"):
    args = [
        "ipa",
        "otptoken-add",
        "--owner",
        owner,
        "--type",
        otptype,
        "--digits",
        str(digits),
        "--algo",
        algo,
        "--no-qrcode",
    ]
    result = host.run_command(args)
    otpuid = re.search(
        r"Unique ID:\s*([a-z0-9-]*)\s+", result.stdout_text
    ).group(1)
    otpuristr = re.search(r"URI:\s*(.*)\s+", result.stdout_text).group(1)
    otpuri = urlparse(otpuristr)
    assert otpuri.netloc == otptype
    query = parse.parse_qs(otpuri.query)
    assert query["algorithm"][0] == algo.upper()
    assert query["digits"][0] == str(digits)
    key = base64.b32decode(query["secret"][0])
    assert len(key) == 35

    hashcls = getattr(hashes, algo.upper())
    if otptype == "hotp":
        return otpuid, HOTP(key, digits, hashcls(), default_backend())
    else:
        period = int(query["period"][0])
        return otpuid, TOTP(key, digits, hashcls(), period, default_backend())


def del_otptoken(host, otpuid):
    tasks.kinit_admin(host)
    host.run_command(["ipa", "otptoken-del", otpuid])


def kinit_otp(host, user, password, otp, success=True):
    tasks.kdestroy_all(host)
    # create armor for FAST
    host.run_command(["kinit", "-n", "-c", ARMOR])
    host.run_command(
        ["kinit", "-T", ARMOR, user],
        stdin_text="{password}{otp}".format(password=password, otp=otp),
        ok_returncode=0 if success else 1,
    )


def ssh_2f(hostname, username, answers_dict, port=22):
    """
    :param hostname: hostname
    :param username: username
    :param answers_dict: dictionary of options with prompt_message and value.
    :param port: port for ssh
    """
    # Handler for server questions
    def answer_handler(title, instructions, prompt_list):
        resp = []
        if title:
            logger.info(title.strip())
        if instructions:
            logger.info(instructions.strip())
        for prmpt in prompt_list:
            prmpt_str = prmpt[0].strip()
            resp.append(answers_dict[prmpt_str])
            logger.info("Prompt is: '%s'", prmpt_str)
            logger.info(
                "Answer to ssh prompt is: '%s'", answers_dict[prmpt_str])
        return resp
    trans = paramiko.Transport((hostname, port))
    trans.connect()
    trans.auth_interactive(username, answer_handler)


def set_sssd_conf(host, add_contents):
    contents = host.get_file_contents(paths.SSSD_CONF, encoding="utf-8")
    file_contents = contents + add_contents
    host.put_file_contents(paths.SSSD_CONF, file_contents)
    tasks.clear_sssd_cache(host)


class TestOTPToken(IntegrationTest):
    """Tests for member manager feature for groups and hostgroups
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        super(TestOTPToken, cls).install(mh)
        master = cls.master

        tasks.kinit_admin(master)
        # create service with OTP auth indicator
        cls.service_name = "otponly/{}".format(master.hostname)
        master.run_command(
            ["ipa", "service-add", cls.service_name, "--auth-ind=otp"]
        )
        # service needs a keytab before user can acquire a ticket for it
        keytab = "/tmp/otponly.keytab"
        master.run_command(
            ["ipa-getkeytab", "-p", cls.service_name, "-k", keytab]
        )
        master.run_command(["rm", "-f", keytab])

        tasks.create_active_user(master, USER, PASSWORD)
        tasks.kinit_admin(master)
        master.run_command(["ipa", "user-mod", USER, "--user-auth-type=otp"])

    @classmethod
    def uninstall(cls, mh):
        cls.master.run_command(["rm", "-f", ARMOR])
        super(TestOTPToken, cls).uninstall(mh)

    def test_otp_auth_ind(self):
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["kvno", self.service_name], ok_returncode=1
        )
        assert "KDC policy rejects request" in result.stderr_text

    def test_hopt(self):
        master = self.master

        tasks.kinit_admin(self.master)
        otpuid, hotp = add_otptoken(master, USER, otptype="hotp")
        master.run_command(["ipa", "otptoken-show", otpuid])
        # normal password login fails
        master.run_command(
            ["kinit", USER], stdin_text=PASSWORD, ok_returncode=1
        )
        # OTP login works
        otpvalue = hotp.generate(0).decode("ascii")
        kinit_otp(master, USER, password=PASSWORD, otp=otpvalue)
        # repeating OTP fails
        kinit_otp(
            master, USER, password=PASSWORD, otp=otpvalue, success=False
        )
        # skipping an OTP is ok
        otpvalue = hotp.generate(2).decode("ascii")
        kinit_otp(master, USER, password=PASSWORD, otp=otpvalue)
        # TGT with OTP auth indicator can get a ticket for OTP-only service
        master.run_command(["kvno", self.service_name])
        result = master.run_command(["klist"])
        assert self.service_name in result.stdout_text

        del_otptoken(master, otpuid)

    def test_totp(self):
        master = self.master

        tasks.kinit_admin(self.master)
        otpuid, totp = add_otptoken(master, USER, otptype="totp")

        otpvalue = totp.generate(int(time.time())).decode("ascii")
        kinit_otp(master, USER, password=PASSWORD, otp=otpvalue)
        # TGT with OTP auth indicator can get a ticket for OTP-only service
        master.run_command(["kvno", self.service_name])
        result = master.run_command(["klist"])
        assert self.service_name in result.stdout_text

        del_otptoken(master, otpuid)

    def test_2fa_enable_single_prompt(self):
        """Test ssh with 2FA when single prompt is enabled.

        Test for : https://pagure.io/SSSD/sssd/issue/3264

        When [prompting/2fa/sshd] with single_prompt = True is set
        then during ssh it should be prompted with given message
        for first and second factor at once.
        """
        cmd = self.master.run_command(['sssd', '--version'])
        sssd_version = platform_tasks.parse_ipa_version(
            cmd.stdout_text.strip())
        if sssd_version <= platform_tasks.parse_ipa_version('1.16.3'):
            pytest.xfail("Fix for https://pagure.io/SSSD/sssd/issue/3264 "
                         "unavailable with sssd-1.16.3")
        master = self.master
        USER1 = 'sshuser1'
        sssd_conf_backup = tasks.FileBackup(master, paths.SSSD_CONF)
        first_prompt = 'Please enter password + OTP token value:'
        add_contents = textwrap.dedent('''
            [prompting/2fa/sshd]
            single_prompt = True
            first_prompt = {0}
            ''').format(first_prompt)
        set_sssd_conf(master, add_contents)
        tasks.create_active_user(master, USER1, PASSWORD)
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'user-mod', USER1, '--user-auth-type=otp'])
        try:
            otpuid, totp = add_otptoken(master, USER1, otptype='totp')
            master.run_command(['ipa', 'otptoken-show', otpuid])
            otpvalue = totp.generate(int(time.time())).decode('ascii')
            answers = {
                first_prompt: '{0}{1}'.format(PASSWORD, otpvalue),
            }
            ssh_2f(master.hostname, USER1, answers)
            # check if user listed in output
            cmd = self.master.run_command(['semanage', 'login', '-l'])
            assert USER1 in cmd.stdout_text
        finally:
            master.run_command(['ipa', 'user-del', USER1])
            self.master.run_command(['semanage', 'login', '-D'])
            sssd_conf_backup.restore()

    def test_2fa_disable_single_prompt(self):
        """Test ssh with 2FA when single prompt is disabled.

        Test for : https://pagure.io/SSSD/sssd/issue/3264

        When [prompting/2fa/sshd] with single_prompt = False is set
        then during ssh it should be prompted with given message
        for first factor and then for second factor.
        """
        cmd = self.master.run_command(['sssd', '--version'])
        sssd_version = platform_tasks.parse_ipa_version(
            cmd.stdout_text.strip())
        if sssd_version <= platform_tasks.parse_ipa_version('1.16.3'):
            pytest.xfail("Fix for https://pagure.io/SSSD/sssd/issue/3264 "
                         "unavailable with sssd-1.16.3")
        master = self.master
        USER2 = 'sshuser2'
        sssd_conf_backup = tasks.FileBackup(master, paths.SSSD_CONF)
        first_prompt = 'Enter first factor:'
        second_prompt = 'Enter second factor:'
        add_contents = textwrap.dedent('''
            [prompting/2fa/sshd]
            single_prompt = False
            first_prompt = {0}
            second_prompt = {1}
            ''').format(first_prompt, second_prompt)
        set_sssd_conf(master, add_contents)
        tasks.create_active_user(master, USER2, PASSWORD)
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'user-mod', USER2, '--user-auth-type=otp'])
        try:
            otpuid, totp = add_otptoken(master, USER2, otptype='totp')
            master.run_command(['ipa', 'otptoken-show', otpuid])
            otpvalue = totp.generate(int(time.time())).decode('ascii')
            answers = {
                first_prompt: PASSWORD,
                second_prompt: otpvalue
            }
            ssh_2f(master.hostname, USER2, answers)
            # check if user listed in output
            cmd = self.master.run_command(['semanage', 'login', '-l'])
            assert USER2 in cmd.stdout_text
        finally:
            master.run_command(['ipa', 'user-del', USER2])
            self.master.run_command(['semanage', 'login', '-D'])
            sssd_conf_backup.restore()
