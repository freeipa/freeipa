#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

import time

from ipapython.dn import DN

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestCACustomSubjectDN(IntegrationTest):
    """
    Test that everything works properly when IPA CA has a custom Subject DN.
    We will also choose a custom Subject Base, that does not have anything
    in common with the CA Subject DN.

    Generating a random DN might be interest, but for now we construct one
    that regression tests some previously encountered issues:

    * KRA authentication failed for all custom subject DNs:
      https://pagure.io/freeipa/issue/8084

    """

    num_replicas = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            cls.master,
            setup_kra=True,
            extra_args=[
                '--subject-base', str(create_custom_subject_base()),
                '--ca-subject', str(create_custom_ca_subject()),
            ],
        )

    def test_kra_authn(self):
        """
        vault-add is sufficient to verify
        https://pagure.io/freeipa/issue/8084.

        """
        self.master.run_command([
            'ipa', 'vault-add', "test1",
            '--password', 'Secret.123', '--type', 'symmetric',
        ])


def create_custom_ca_subject():
    return DN(
        ('CN', 'IPA CA'),
        ('O', 'Corporation {} Inc.'.format(int(time.time()))),
    )


def create_custom_subject_base():
    return DN(('O', 'Red Hat Inc.'))
