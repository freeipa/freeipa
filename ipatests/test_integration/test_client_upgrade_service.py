#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""Tests for ipa-client-upgrade.service.

The client configuration migrations that used to run only from the
ipa-client %post scriptlet are driven by a Type=oneshot systemd unit,
ipa-client-upgrade.service, so that they also run on image-mode
(rpm-ostree) deployments where RPM scriptlets never run on the host.

The unit is pulled into the boot transaction by an sssd.service drop-in
(Wants=), guarded by ConditionDirectoryNotEmpty on the sysrestore
directory, and short-circuited by a per-version stamp file so it is cheap
to leave in place across every boot.
"""

from __future__ import absolute_import

import os

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

UPGRADE_SERVICE = "ipa-client-upgrade.service"
UPGRADE_STAMP = os.path.join(paths.IPA_CLIENT_SYSRESTORE, ".upgrade-version")
SSSD_DROPIN = "sssd-ipa-client-upgrade.conf"
KRB5_INCLUDEDIR = "includedir /var/lib/sss/pubconf/krb5.include.d/"


class TestClientUpgradeService(IntegrationTest):
    topology = 'line'
    num_clients = 1

    @property
    def client(self):
        return self.clients[0]

    def _show(self, unit, prop):
        """Return the value of a single systemd unit property."""
        result = self.client.run_command(
            ['systemctl', 'show', unit, '-p', prop, '--value']
        )
        return result.stdout_text.strip()

    def _trigger_via_sssd(self):
        """Run the oneshot the way a deployed host does and return its Result.

        Restarting sssd re-enqueues the Wants= dependency from the drop-in,
        which pulls in the upgrade unit; the Before= ordering means the
        restart does not return until the oneshot has finished. A plain
        start of sssd would be a no-op here (it is already active) and would
        not re-pull the dependency, so restart is required.
        """
        self.client.run_command(['systemctl', 'restart', 'sssd.service'])
        return self._show(UPGRADE_SERVICE, 'Result')

    def _start_unit(self):
        """Run the oneshot directly and return its Result."""
        # reset-failed so a Result from a previous run does not linger
        self.client.run_command(
            ['systemctl', 'reset-failed', UPGRADE_SERVICE], raiseonerr=False
        )
        self.client.run_command(['systemctl', 'start', UPGRADE_SERVICE])
        return self._show(UPGRADE_SERVICE, 'Result')

    def _stamp_exists(self):
        result = self.client.run_command(
            ['test', '-f', UPGRADE_STAMP], raiseonerr=False
        )
        return result.returncode == 0

    def test_unit_installed(self):
        """The unit ships as a oneshot guarded on the sysrestore directory."""
        unit = self.client.run_command(
            ['systemctl', 'cat', UPGRADE_SERVICE]
        ).stdout_text
        assert 'Type=oneshot' in unit
        assert 'ipa-client-upgrade' in unit
        assert 'ConditionDirectoryNotEmpty' in unit

    def test_dropin_wires_activation_from_sssd(self):
        """The sssd.service drop-in pulls the unit into the boot transaction.

        Activation must come from the drop-in rather than a preset so it
        also takes effect on image-mode systems, where no enablement step
        runs on the deployed host.
        """
        dropins = self._show('sssd.service', 'DropInPaths')
        assert SSSD_DROPIN in dropins

        wants = self._show('sssd.service', 'Wants')
        assert UPGRADE_SERVICE in wants.split()

    def test_unit_ordered_before_sssd(self):
        """Migrations must run before the services that consume the config."""
        before = self._show(UPGRADE_SERVICE, 'Before')
        assert 'sssd.service' in before.split()

    def test_service_runs_via_sssd_on_enrolled_client(self):
        """Restarting sssd pulls in the unit, which records the stamp."""
        self.client.run_command(['rm', '-f', UPGRADE_STAMP])

        assert self._trigger_via_sssd() == 'success'
        assert self._stamp_exists()

        stamp = self.client.get_file_contents(
            UPGRADE_STAMP, encoding='utf-8'
        ).strip()
        assert stamp

    def test_service_is_idempotent(self):
        """A second run is a no-op short-circuited by the version stamp."""
        before = self.client.get_file_contents(
            UPGRADE_STAMP, encoding='utf-8'
        ).strip()

        assert self._trigger_via_sssd() == 'success'

        after = self.client.get_file_contents(
            UPGRADE_STAMP, encoding='utf-8'
        ).strip()
        assert after == before

    def test_service_applies_migration(self):
        """Running the unit performs the client configuration migration.

        Inject the obsolete sssd krb5 includedir into krb5.conf, clear the
        stamp so the migration runs, restart sssd to pull the unit in, and
        confirm the unit removed it.
        """
        krb5 = self.client.get_file_contents(paths.KRB5_CONF, encoding='utf-8')
        if KRB5_INCLUDEDIR not in krb5:
            self.client.put_file_contents(
                paths.KRB5_CONF, krb5 + "\n" + KRB5_INCLUDEDIR + "\n"
            )
        self.client.run_command(['rm', '-f', UPGRADE_STAMP])

        assert self._trigger_via_sssd() == 'success'

        krb5 = self.client.get_file_contents(paths.KRB5_CONF, encoding='utf-8')
        assert KRB5_INCLUDEDIR not in krb5

    def test_service_skipped_on_unenrolled_host(self):
        """After uninstall the unit is a no-op: no migration, no stamp.

        sssd is unconfigured once the client is unenrolled, so this starts
        the unit directly to confirm its own guard (the enrollment check and
        ConditionDirectoryNotEmpty) short-circuits it.
        """
        tasks.uninstall_client(self.clients[0])
        self.client.run_command(['rm', '-f', UPGRADE_STAMP])

        assert self._start_unit() == 'success'
        assert not self._stamp_exists()
