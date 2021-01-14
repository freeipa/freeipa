#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests to verify that the upgrade script works.
"""
from __future__ import absolute_import

import base64
import os
from cryptography.hazmat.primitives import serialization

from ipaplatform.paths import paths
from ipapython.dn import DN
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestUpgrade(IntegrationTest):
    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_invoke_upgrader(self):
        cmd = self.master.run_command(['ipa-server-upgrade'],
                                      raiseonerr=False)
        assert ("DN: cn=Schema Compatibility,cn=plugins,cn=config does not \
                exists or haven't been updated" not in cmd.stdout_text)
        assert cmd.returncode == 0

    def test_double_encoded_cacert(self):
        """Test for BZ 1644874

        In old IPA version, the entry cn=CAcert,cn=ipa,cn=etc,$basedn
        could contain a double-encoded cert, which leads to ipa-server-upgrade
        failure.
        Force a double-encoded value then call upgrade to check the fix.
        """
        # Read the current entry from LDAP
        ldap = self.master.ldap_connect()
        basedn = self.master.domain.basedn  # pylint: disable=no-member
        dn = DN(('cn', 'CAcert'), ('cn', 'ipa'), ('cn', 'etc'), basedn)
        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        # Extract the certificate as DER then double-encode
        cacert = entry['cacertificate;binary'][0]
        cacert_der = cacert.public_bytes(serialization.Encoding.DER)
        cacert_b64 = base64.b64encode(cacert_der)
        # overwrite the value with double-encoded cert
        entry.single_value['cACertificate;binary'] = cacert_b64
        ldap.update_entry(entry)  # pylint: disable=no-member

        # try the upgrade
        self.master.run_command(['ipa-server-upgrade'])

        # reconnect to the master (upgrade stops 389-ds)
        ldap = self.master.ldap_connect()
        # read the value after upgrade, should be fixed
        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        try:
            _cacert = entry['cacertificate;binary']
        except ValueError:
            raise AssertionError('%s contains a double-encoded cert'
                                 % entry.dn)

    def test_admin_root_alias_upgrade_CVE_2020_10747(self):
        # Test upgrade for CVE-2020-10747 fix
        # https://bugzilla.redhat.com/show_bug.cgi?id=1810160
        rootprinc = "root@{}".format(self.master.domain.realm)
        self.master.run_command(
            ["ipa", "user-remove-principal", "admin", rootprinc]
        )
        result = self.master.run_command(["ipa", "user-show", "admin"])
        assert rootprinc not in result.stdout_text

        self.master.run_command(['ipa-server-upgrade'])
        result = self.master.run_command(["ipa", "user-show", "admin"])
        assert rootprinc in result.stdout_text

    def test_kra_detection(self):
        """Test that ipa-server-upgrade correctly detects KRA presence

        Test for https://pagure.io/freeipa/issue/8596
        When the directory /var/lib/pki/pki-tomcat/kra/ exists, the upgrade
        wrongly assumes that KRA component is installed and crashes.
        The test creates an empty dir and calls kra.is_installed()
        to make sure that KRA detection is not based on the directory
        presence.
        Note: because of issue https://github.com/dogtagpki/pki/issues/3397
        ipa-server-upgrade fails even with the kra detection fix. That's
        why the test does not exercise the whole ipa-server-upgrade command
        but only the KRA detection part.
        """
        kra_path = os.path.join(paths.VAR_LIB_PKI_TOMCAT_DIR, "kra")
        try:
            self.master.run_command(["mkdir", "-p", kra_path])
            script = (
                "from ipalib import api; "
                "from ipaserver.install import krainstance; "
                "api.bootstrap(); "
                "api.finalize(); "
                "kra = krainstance.KRAInstance(api.env.realm); "
                "print(kra.is_installed())"
            )

            result = self.master.run_command(['python3', '-c', script],
                                             raiseonerr=False)
            if result.returncode != 0:
                # Retry with python instead of python3
                result = self.master.run_command(['python', '-c', script])
            assert "False" in result.stdout_text
        finally:
            self.master.run_command(["rmdir", kra_path])
