#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import time

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

WAIT_AFTER_ARCHIVE = 45  # give some time to replication


class TestInstallKRA(IntegrationTest):
    """
    Test if vault feature behaves as expected, when KRA is installed or not
    installed on replica
    """
    num_replicas = 1
    topology = 'star'

    vault_password = "password"
    vault_data = "SSBsb3ZlIENJIHRlc3RzCg=="
    vault_user = "vault_user"
    vault_user_password = "vault_user_password"
    vault_name_master = "ci_test_vault_master"
    vault_name_master2 = "ci_test_vault_master2"
    vault_name_master3 = "ci_test_vault_master3"
    vault_name_replica_without_KRA = "ci_test_vault_replica_without_kra"
    shared_vault_name_replica_without_KRA = ("ci_test_shared"
                                             "_vault_replica_without_kra")
    vault_name_replica_with_KRA = "ci_test_vault_replica_with_kra"
    vault_name_replica_KRA_uninstalled = "ci_test_vault_replica_KRA_uninstalled"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master,
                             setup_kra=True,
                             random_serial=cls.random_serial)
        # do not install KRA on replica, it is part of test
        tasks.install_replica(cls.master, cls.replicas[0], setup_kra=False)

    def _retrieve_secret(self, vault_names=[]):
        # try to retrieve secret from vault on both master and replica
        for vault_name in vault_names:
            self.master.run_command([
                "ipa", "vault-retrieve",
                vault_name,
                "--password", self.vault_password,
            ])

            self.replicas[0].run_command([
                "ipa", "vault-retrieve",
                vault_name,
                "--password", self.vault_password,
            ])

    def test_create_and_retrieve_vault_master(self):
        # create vault
        self.master.run_command([
            "ipa", "vault-add",
            self.vault_name_master,
            "--password", self.vault_password,
            "--type", "symmetric",
        ])

        # archive secret
        self.master.run_command([
            "ipa", "vault-archive",
            self.vault_name_master,
            "--password", self.vault_password,
            "--data", self.vault_data,
        ])
        time.sleep(WAIT_AFTER_ARCHIVE)

        self._retrieve_secret([self.vault_name_master])

    def test_create_and_retrieve_vault_replica_without_kra(self):
        # create vault
        self.replicas[0].run_command([
            "ipa", "vault-add",
            self.vault_name_replica_without_KRA,
            "--password", self.vault_password,
            "--type", "symmetric",
        ])

        # archive secret
        self.replicas[0].run_command([
            "ipa", "vault-archive",
            self.vault_name_replica_without_KRA,
            "--password", self.vault_password,
            "--data", self.vault_data,
        ])
        time.sleep(WAIT_AFTER_ARCHIVE)

        self._retrieve_secret([self.vault_name_replica_without_KRA])

    def test_create_and_retrieve_shared_vault_replica_without_kra(self):
        # create vault
        self.replicas[0].run_command([
            "ipa", "vault-add",
            self.shared_vault_name_replica_without_KRA,
            "--shared",
            "--type", "standard",
        ])

        # archive secret
        self.replicas[0].run_command([
            "ipa", "vault-archive",
            self.shared_vault_name_replica_without_KRA,
            "--shared",
            "--data", self.vault_data,
        ])
        time.sleep(WAIT_AFTER_ARCHIVE)

        # add non-admin user
        self.replicas[0].run_command([
            'ipa', 'user-add', self.vault_user,
            '--first', self.vault_user,
            '--last', self.vault_user,
            '--password'],
            stdin_text=self.vault_user_password)

        # add it to vault
        self.replicas[0].run_command([
            "ipa", "vault-add-member",
            self.shared_vault_name_replica_without_KRA,
            "--shared",
            "--users", self.vault_user,
        ])

        self.replicas[0].run_command([
            'kdestroy', '-A'])

        user_kinit = "%s\n%s\n%s\n" % (self.vault_user_password,
                                       self.vault_user_password,
                                       self.vault_user_password)

        self.replicas[0].run_command([
            'kinit', self.vault_user],
            stdin_text=user_kinit)

        # TODO: possibly refactor with:
        # self._retrieve_secret([self.vault_name_replica_without_KRA])

        self.replicas[0].run_command([
            "ipa", "vault-retrieve",
            "--shared",
            self.shared_vault_name_replica_without_KRA,
            "--out=test.txt"])

        self.replicas[0].run_command([
            'kdestroy', '-A'])

        tasks.kinit_admin(self.replicas[0])


    def test_create_and_retrieve_vault_replica_with_kra(self):

        # install KRA on replica
        tasks.install_kra(self.replicas[0], first_instance=False)

        # create vault
        self.replicas[0].run_command([
            "ipa", "vault-add",
            self.vault_name_replica_with_KRA,
            "--password", self.vault_password,
            "--type", "symmetric",
        ])

        # archive secret
        self.replicas[0].run_command([
            "ipa", "vault-archive",
            self.vault_name_replica_with_KRA,
            "--password", self.vault_password,
            "--data", self.vault_data,
        ])
        time.sleep(WAIT_AFTER_ARCHIVE)

        self._retrieve_secret([self.vault_name_replica_with_KRA])

        # ################ master #################
        # test master again after KRA was installed on replica
        # create vault
        self.master.run_command([
            "ipa", "vault-add",
            self.vault_name_master2,
            "--password", self.vault_password,
            "--type", "symmetric",
        ])

        # archive secret
        self.master.run_command([
            "ipa", "vault-archive",
            self.vault_name_master2,
            "--password", self.vault_password,
            "--data", self.vault_data,
        ])
        time.sleep(WAIT_AFTER_ARCHIVE)

        self._retrieve_secret([self.vault_name_master2])

        # ############### old vaults ###############
        # test if old vaults are still accessible
        self._retrieve_secret([
            self.vault_name_master,
            self.vault_name_replica_without_KRA,
        ])
