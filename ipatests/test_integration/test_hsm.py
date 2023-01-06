#
# Copyright (C) 2022 FreeIPA Contributors see COPYING for license
#

import random
import string

from ipatests.test_integration.test_installation import InstallTestBase1
from ipatests.pytest_ipa.integration import tasks


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
        tasks.install_master(
            cls.master, setup_dns=True,
            extra_args=(
                '--token-name', token_name,
                '--token-library-path', hsm_lib_path,
                '--token-password', token_passwd
            )
        )
