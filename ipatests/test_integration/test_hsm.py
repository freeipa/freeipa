#
# Copyright (C) 2022 FreeIPA Contributors see COPYING for license
#

import os.path
import random
import string

from ipatests.test_integration.test_installation import InstallTestBase1
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths


hsm_lib_path = '/usr/lib64/pkcs11/libsofthsm2.so'


def create_hsm_token(host):
    """Helper method to create an hsm token using softhsm"""
    token_name = ''.join(
        random.choice(string.ascii_letters) for i in range(10)
    )
    token_passwd = ''.join(
        random.choice(string.ascii_letters) for i in range(10)
    )
    # remove the token if already exist
    host.run_command(
        ['softhsm2-util', '--delete-token', '--token', token_name],
        raiseonerr=False
    )
    host.run_command(
        ['runuser', '-u', 'pkiuser', '--', 'softhsm2-util', '--init-token',
         '--free', '--pin', token_passwd, '--so-pin', token_passwd,
         '--label', token_name]
    )
    return (token_name, token_passwd)


def find_softhsm_token_files(host, token):
    result = host.run_command([
        paths.MODUTIL, '-list', 'libsofthsm2',
        '-dbdir', paths.PKI_TOMCAT_ALIAS_DIR
    ])

    serial = None
    state = 'token_name'
    for line in result.stdout_text.split('\n'):
        if state == 'token_name' and 'Token Name:' in line.strip():
            (_label, tokenname) = line.split(':',1)
            if tokenname.strip() == token:
                state = 'serial'
        elif state == 'serial' and 'Token Serial Number' in line.strip():
            (_label, serial) = line.split(':',1)
            serial = serial.strip()
            serial = "{}-{}".format(serial[0:4], serial[4:])
            break

    if serial is None:
        raise RuntimeError("can't find softhsm token serial for %s"
                           % token)

    result = host.run_command(
        ['ls', '-l', '/var/lib/softhsm/tokens/'])
    serialdir = None
    for r in result.stdout_text.split('\n'):
        if serial in r:
            dirname = r.split()[-1:][0]
            serialdir = f'/var/lib/softhsm/tokens/{dirname}'
            break
    if serialdir is None:
        raise RuntimeError("can't find softhsm token directory for %s"
                           % serial)
    result = host.run_command(['ls', '-1', serialdir])
    return serialdir, [
        os.path.join(serialdir, file)
        for file in result.stdout_text.strip().split('\n')
    ]


class TestHSMInstall(InstallTestBase1):

    num_replicas = 3

    @classmethod
    def install(cls, mh):
        # create a hsm token
        cls.master.run_command(
            ['dnf', '-y', 'copr', 'enable', 'rcritten/freeipa'])
        cls.master.run_command(['dnf', '-y', 'update'])
        cls.master.run_command(['usermod', 'pkiuser', '-a', '-G', 'ods'])
        token_name, token_passwd = create_hsm_token(cls.master)
        cls.token_password = token_passwd
        cls.token_name = token_name
        tasks.install_master(
            cls.master, setup_dns=True,
            extra_args=(
                '--token-name', token_name,
                '--token-library-path', hsm_lib_path,
                '--token-password', token_passwd
            )
        )
        serialdir, token_files = find_softhsm_token_files(
            cls.master, token_name
        )
        for replica in cls.replicas:
            tasks.copy_files(cls.master, replica, token_files)
            replica.run_command(
                ['chown', '-R', 'pkiuser:pkiuser', serialdir]
            )

    # For any subsequent KRA installations the token directory
    # needs to be re-copied so all the keys are available. The
    # KRA is first installed on replica0.
    def test_replica1_ipa_kra_install(self):
        serialdir, token_files = find_softhsm_token_files(
            self.master, self.token_name
        )
        for server in (self.replicas[0], self.replicas[2], self.master):
            tasks.copy_files(self.replicas[1], server, token_files)
            server.run_command(
                ['chown', '-R', 'pkiuser:pkiuser', serialdir]
            )
        super(TestHSMInstall, self).test_replica1_ipa_kra_install()

    def test_replica2_with_ca_kra_install(self):
        serialdir, token_files = find_softhsm_token_files(
            self.master, self.token_name
        )
        for server in (self.replicas[0], self.replicas[2], self.master):
            tasks.copy_files(self.replicas[1], server, token_files)
            server.run_command(
                ['chown', '-R', 'pkiuser:pkiuser', serialdir]
            )
        super(TestHSMInstall, self).test_replica2_with_ca_kra_install()
