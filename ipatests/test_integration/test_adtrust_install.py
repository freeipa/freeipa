#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for ipa-adtrust-install utility"""

import re

from ipatests.test_integration.base import IntegrationTest


class TestIpaAdTrustInstall(IntegrationTest):
    topology = 'line'
    num_replicas = 1

    def test_samba_config_file(self):
        """Check that ipa-adtrust-install generates sane smb.conf

        This is regression test for issue
        https://pagure.io/freeipa/issue/6951
        """
        self.master.run_command(
            ['ipa-adtrust-install', '-a', 'Secret123', '--add-sids', '-U'])
        res = self.master.run_command(['testparm', '-s'])
        assert 'ERROR' not in (res.stdout_text + res.stderr_text)

    def test_warnings_after_ad_trust_agents_setup(self):
        """ Check that warning about ipa and sssd restart is displayed.

        Regression test for https://bugzilla.redhat.com/1782658
        """
        cmd_input = (
            # admin password:
            self.master.config.admin_password + '\n' +
            # WARNING: The smb.conf already exists. Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            'yes\n'
            # Enable trusted domains support in slapi-nis? [no]:
            '\n' +
            # WARNING: 1 IPA masters are not yet able to serve information
            # about users from trusted forests.
            # Installer can add them to the list of IPA masters allowed to
            # access information about trusts.
            # If you choose to do so, you also need to restart LDAP service on
            # those masters.
            # Refer to ipa-adtrust-install(1) man page for details.
            # IPA master[replica1.testrelm.test]?[no]:
            'yes\n'
        )
        expected_re = '"ipactl restart".+"systemctl restart sssd"'
        res = self.master.run_command(['ipa-adtrust-install', '--add-agents'],
                                      stdin_text=cmd_input)
        assert re.search(expected_re, res.stdout_text, re.DOTALL)
