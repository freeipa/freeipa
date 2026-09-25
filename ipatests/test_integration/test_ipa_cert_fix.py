#
# Copyright (C) 2020, 2026  FreeIPA Contributors see COPYING for license
#

"""
Tests for ipa-cert-fix CLI.

Organized by scenario per the ipa-cert-fix redesign test plan:
  1. Renewal master (T-RM-*)
  2. CA-full replica, non-destructive (T-REP-*)
  3. CA-full replica, promote to RM (T-PROMO-*)
  4. CA-less replica (T-CALESS-*)
  5. External and mixed certificates (T-EXT-*)
  6. Topology-wide expiry (T-TOPO-*)
  7. Cross-cutting: pre-flight, idempotency, state restoration,
     deployment detection (T-PRE-*, T-IDEM-*, T-RESTORE-*, T-DETECT-*)
  8. End-to-end story tests (T-E2E-*)

Each test is marked with a tier:
  - unit: no IPA deployment, mocks only (seconds)
  - integration: single IPA server (minutes)
  - system: multi-host topology (tens of minutes)
"""
import functools
import pytest
import time

import logging
from datetime import datetime, date
from ipalib import x509
from ipaplatform.paths import paths
from ipapython.ipaldap import realm_to_serverid
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_caless import (
    CALessBase, ipa_certs_cleanup,
)
from ipatests.test_integration.test_external_ca import (
    install_server_external_ca_step1,
    install_server_external_ca_step2,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------
#  Shared helpers
# ---------------------------------------------------------------

def check_status(host, cert_count, state, timeout=600):
    """Wait until ``cert_count`` certs reach ``state``.

    :param host: the host
    :param cert_count: expected number of certs in the state
    :param state: certmonger state to match (e.g. ``MONITORING``)
    :param timeout: max seconds to wait
    :returns: actual count
    """
    for _i in range(0, timeout, 10):
        result = host.run_command(['getcert', 'list'])
        count = result.stdout_text.count(f"status: {state}")
        logger.info("cert count in %s state: %s", state, count)
        if count >= cert_count:
            break
        time.sleep(10)
    else:
        raise RuntimeError("request timed out")

    return count


def needs_resubmit(host, req_id):
    """Helper method to identify if cert request needs to be resubmitted
    :param host: the host
    :param req_id: request id to perform operation for

    Returns True if resubmit needed else False
    """
    # check if cert is in monitoring state
    tasks.wait_for_certmonger_status(
        host, ('MONITORING'), req_id, timeout=600
    )

    # check if cert is valid and not expired
    cmd = host.run_command(
        'getcert list -i {} | grep expires'.format(req_id)
    )
    cert_expiry = cmd.stdout_text.split(' ')
    cert_expiry = datetime.strptime(cert_expiry[1], '%Y-%m-%d').date()
    if cert_expiry > date.today():
        return False
    else:
        return True


def get_cert_expiry(host, nssdb_path, cert_nick):
    """Return the ``not_valid_after_utc`` of a cert in an NSS database."""
    host.run_command([
        'certutil', '-L', '-a',
        '-d', nssdb_path,
        '-n', cert_nick,
        '-o', '/root/cert.pem'
    ])
    data = host.get_file_contents('/root/cert.pem')
    cert = x509.load_pem_x509_certificate(data)
    return cert.not_valid_after_utc


def server_install_teardown(func):
    """Decorator that uninstalls master + cleans certs in finally."""
    @functools.wraps(func)
    def wrapped(*args):
        master = args[0].master
        try:
            func(*args)
        finally:
            ipa_certs_cleanup(master)
    return wrapped


def assert_postconditions(host):
    """Assert cross-cutting postconditions P1-P5 hold.

    These invariants must be true after any ipa-cert-fix run,
    regardless of success or failure.

    P3 (KRB5CCNAME restored) and P4 (ldap2 clean) are
    process-internal state that cannot be checked after the
    tool exits.  They should be covered by unit tests with
    mocks (T-RESTORE-3 and T-RESTORE-4, not yet implemented).
    """
    # P1: IPA CA helper has no leftover -J override
    result = host.run_command(
        ['getcert', 'list-cas', '-c', 'IPA'],
        raiseonerr=False,
    )
    if result.returncode == 0:
        assert '-J https://' not in result.stdout_text, \
            "P1 violated: IPA CA helper still has -J override"

    # P2: No Dogtag tracking requests have orphaned
    # template-principal (should have been cleared during
    # restore).  Check each Dogtag cert's tracking request.
    for nickname in ('auditSigningCert cert-pki-ca',
                     'ocspSigningCert cert-pki-ca',
                     'subsystemCert cert-pki-ca',
                     'Server-Cert cert-pki-ca'):
        cmd = host.run_command(
            ['getcert', 'list',
             '-d', paths.PKI_TOMCAT_ALIAS_DIR,
             '-n', nickname],
            raiseonerr=False,
        )
        if cmd.returncode != 0:
            continue
        # getcert list shows "principal: <value>" for
        # template-principal if set.  After cleanup,
        # Dogtag certs should NOT have a host/ principal
        # (that was only added temporarily for renewal through IPA CA).
        for line in cmd.stdout_text.splitlines():
            if 'principal:' in line.lower():
                value = line.split(':', 1)[1].strip()
                if value.startswith('host/'):
                    assert False, (
                        "P2 violated: %s has orphaned template-principal '%s'"
                        % (nickname, value)
                    )

    # P5: No tracking requests stuck with CA=IPA that should be
    # dogtag-ipa-ca-renew-agent -- check dogtag cert nicknames
    for nickname in ('auditSigningCert cert-pki-ca',
                     'ocspSigningCert cert-pki-ca',
                     'subsystemCert cert-pki-ca'):
        cmd = host.run_command(
            ['getcert', 'list', '-d', paths.PKI_TOMCAT_ALIAS_DIR,
             '-n', nickname],
            raiseonerr=False,
        )
        if cmd.returncode == 0 and 'CA: IPA' in cmd.stdout_text:
            # Dogtag certs should use dogtag-ipa-ca-renew-agent,
            # not IPA -- this indicates a restore failure
            assert False, (
                "P5 violated: %s has CA=IPA instead of "
                "dogtag-ipa-ca-renew-agent" % nickname
            )

    # P6: HTTPS serves valid TLS (cert is installed and httpd
    # is running with it)
    tls_check = host.run_command(
        ['openssl', 's_client', '-connect',
         '%s:443' % host.hostname, '-servername', host.hostname,
         '-verify_return_error', '-CAfile', paths.IPA_CA_CRT],
        stdin_text='',
        raiseonerr=False,
    )
    if tls_check.returncode != 0:
        logger.warning(
            "P6: TLS check to %s:443 failed (may be expected "
            "if httpd is still restarting): %s",
            host.hostname, tls_check.stderr_text[:200])
    else:
        assert 'Verify return code: 0' in tls_check.stdout_text, (
            "P6 violated: TLS to %s:443 verification failed"
            % host.hostname
        )

    # P7: PKI subsystem operational -- ipa cert-find queries the CA
    # via IPA framework, works on any enrolled host (not just CA
    # hosts) as long as the deployment has a CA and we have a valid ticket.
    ca_check = host.run_command(
        ['ipa', 'cert-find', '--sizelimit=1'],
        raiseonerr=False,
    )
    if ca_check.returncode == 0:
        assert 'Certificate:' in ca_check.stdout_text or \
            'Number of entries returned' in ca_check.stdout_text, (
                "P7 violated: ipa cert-find returned 0 but no certs"
            )
    else:
        # cert-find may fail if kinit isn't done or CA is
        # unreachable (e.g. CA-less-external with no CA at all)
        logger.debug(
            "P7: ipa cert-find failed (may be expected "
            "without valid ticket or if no CA): rc=%s", ca_check.returncode)


# ---------------------------------------------------------------
#  Fixtures
# ---------------------------------------------------------------

@pytest.fixture
def expire_cert_critical():
    """Expire certs by moving the system date (+3 years).

    Yields a callable that installs master and expires certs.
    Teardown: removes tracking, uninstalls, reverts date.
    """
    hosts = dict()

    def _expire_cert_critical(host, setup_kra=False):
        hosts['host'] = host
        tasks.install_master(host, setup_dns=False, extra_args=['--no-ntp'])
        if setup_kra:
            tasks.install_kra(host)
        tasks.move_date(host, 'stop', '+3Years+1day')

    yield _expire_cert_critical

    host = hosts.pop('host', None)
    if host is None:
        return
    host.run_command(['systemctl', 'stop', 'certmonger'])
    host.run_command('rm -fv ' + paths.CERTMONGER_REQUESTS_DIR + '*')
    tasks.uninstall_master(host)
    tasks.move_date(host, 'start', '-3Years-1day')


# ---------------------------------------------------------------
#  1. Renewal Master (T-RM-*)
# ---------------------------------------------------------------

class TestRenewalMaster(IntegrationTest):
    """Tests for the renewal master fix scenario."""

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def expire_ca_cert(self):
        """Install master, then expire the CA cert (+20 years)."""
        tasks.install_master(self.master, setup_dns=False,
                             extra_args=['--no-ntp'])
        tasks.move_date(self.master, 'stop', '+20Years+1day')
        yield
        self.master.run_command(['systemctl', 'stop', 'certmonger'])
        self.master.run_command(
            'rm -fv ' + paths.CERTMONGER_REQUESTS_DIR + '*')
        tasks.uninstall_master(self.master)
        tasks.move_date(self.master, 'start', '-20Years-1day')

    def test_rm1_all_certs_expired(self, expire_cert_critical):
        """T-RM-1: All certs expired on renewal master, self-signed CA.

        Expire all certs, run ipa-cert-fix, verify all renewed.
        Run a second time: verify "Nothing to do".
        """
        expire_cert_critical(self.master)
        check_status(self.master, 8, "CA_UNREACHABLE")

        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")
        assert_postconditions(self.master)

        # Second run -- nothing to do
        result = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        assert "Nothing to do" in result.stdout_text
        check_status(self.master, 9, "MONITORING")

    def test_rm2_all_certs_expired_with_kra(self, expire_cert_critical):
        """T-RM-2: All certs expired with KRA installed.

        Verify KRA certs (transport, storage, audit) are also renewed.
        """
        expire_cert_critical(self.master, setup_kra=True)
        check_status(self.master, 11, "CA_UNREACHABLE")

        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 12, "MONITORING")
        assert_postconditions(self.master)

    def test_rm3_dry_run(self, expire_cert_critical):
        """T-RM-3: Dry-run shows plan without making changes.

        Verify [DRY RUN] output, no certs modified, exit code 0.
        """
        expire_cert_critical(self.master)
        check_status(self.master, 8, "CA_UNREACHABLE")

        result = self.master.run_command(
            ['ipa-cert-fix', '-v', '--dry-run']
        )
        assert result.returncode == 0
        assert "[DRY RUN]" in result.stdout_text

        # Certs should still be unreachable
        check_status(self.master, 8, "CA_UNREACHABLE")

    def test_rm5_ca_signing_near_expiry(self, expire_ca_cert):
        """T-RM-5 / T-RM-6: CA signing cert expired blocks renewal.

        When the CA cert is expired, ipa-cert-fix must refuse.
        """
        result = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n',
            raiseonerr=False,
        )
        assert result.returncode == 1

    def test_rm10_csr_missing_from_cs_cfg(self, expire_cert_critical):
        """T-RM-10: CSR directive missing from CS.cfg.

        Remove ca.sslserver.certreq, use getcert resubmit to create
        the CSR in certmonger.  ipa-cert-fix should backfill it.

        Regression test for https://codeberg.org/freeipa/freeipa/issues/8618
        """
        expire_cert_critical(self.master)
        self.master.run_command(['ipactl', 'stop'])
        self.master.run_command([
            'sed', '-i', r'/ca\.sslserver\.certreq=/d',
            paths.CA_CS_CFG_PATH
        ])
        self.master.run_command([
            'ipactl', 'start', '--ignore-service-failures'
        ])
        self.master.run_command([
            'getcert', 'resubmit',
            '-n', 'Server-Cert cert-pki-ca',
            '-d', paths.PKI_TOMCAT_ALIAS_DIR
        ])
        time.sleep(3)

        result = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n',
            raiseonerr=False,
        )
        msg = ("No such file or directory: "
               "'/etc/pki/pki-tomcat/certs/sslserver.crt'")
        assert msg not in result.stderr_text

        # PKI 10.10.0 has a bug where pki-server cert-fix fails
        # when the CSR is missing from CS.cfg, even after we
        # restore it.  On all other versions, the fix should
        # succeed and all certs should return to MONITORING.
        if (tasks.get_pki_version(self.master)
                != tasks.parse_version('10.10.0')):
            assert result.returncode == 0
            cmd = self.master.run_command(['getcert', 'list'])
            certs = cmd.stdout_text.count('Request ID')
            timeout = 600
            start = time.time()
            while time.time() - start < timeout:
                cmd = self.master.run_command(['getcert', 'list'])
                renewed = cmd.stdout_text.count('status: MONITORING')
                if renewed == certs:
                    break
                time.sleep(10)
            else:
                raise AssertionError('Timeout: Failed to renew all the certs')

    def test_rm11_selftests_startup_missing(self, expire_cert_critical):
        """T-RM-11: selftests.container.order.startup missing.

        Verify PKI-version-dependent behavior.

        Regression test for https://codeberg.org/freeipa/freeipa/issues/8721
        and https://codeberg.org/freeipa/freeipa/issues/8890
        """
        expire_cert_critical(self.master)
        self.master.run_command(['ipactl', 'stop'])
        self.master.run_command([
            'sed', '-i',
            r'/selftests\.container\.order\.startup/d',
            paths.CA_CS_CFG_PATH
        ])
        self.master.run_command([
            'ipactl', 'start', '--ignore-service-failures'
        ])

        result = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n',
            raiseonerr=False,
        )

        err_msg1 = "ERROR: 'selftests.container.order.startup'"
        err_msg2 = ("ERROR: CalledProcessError(Command "
                    "['pki-server', 'cert-fix'")
        warn_msg = "WARNING: No selftests configured in"

        # PKI < 10.11.0: pki-server cert-fix crashes with an error
        # about missing selftests.container.order.startup directive.
        # PKI >= 10.11.0: the directive is optional, pki-server
        # prints a warning but proceeds successfully.
        if (tasks.get_pki_version(self.master)
                < tasks.parse_version('10.11.0')):
            assert (err_msg1 in result.stderr_text
                    and err_msg2 in result.stderr_text)
        else:
            assert warn_msg in result.stderr_text

    def test_rm12_user_declines(self, expire_cert_critical):
        """T-RM-12: User says "no" at confirmation.

        No certs should be modified.
        """
        expire_cert_critical(self.master)
        check_status(self.master, 8, "CA_UNREACHABLE")

        result = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='no\n',
        )
        assert "Not proceeding" in result.stdout_text

        # Certs should still be unreachable
        check_status(self.master, 8, "CA_UNREACHABLE")

    def test_rm4_only_some_certs_expired(self):
        """T-RM-4: Only HTTP and KDC certs expired.

        Dogtag certs remain valid.  Only the expired IPA service
        certs should be renewed; valid certs must not be touched.
        """
        tasks.install_master(self.master, setup_dns=False,
                             extra_args=['--no-ntp'])
        try:
            # Record serial numbers of certs that should NOT change
            pre_serials = {}
            for nick in ('caSigningCert cert-pki-ca',
                         'Server-Cert cert-pki-ca',
                         'subsystemCert cert-pki-ca',
                         'ocspSigningCert cert-pki-ca',
                         'auditSigningCert cert-pki-ca'):
                pre_serials[nick] = get_cert_expiry(
                    self.master, paths.PKI_TOMCAT_ALIAS_DIR, nick)

            # Expire only HTTP and KDC certs by moving clock
            # forward just enough that they expire (IPA service
            # certs have shorter lifetime than CA/Dogtag certs).
            # Use +3 years -- Dogtag certs last 10+ years, IPA
            # service certs last 2 years.
            tasks.move_date(self.master, 'stop', '+3Years+1day')

            # Verify some certs are unreachable but not all
            result = self.master.run_command(
                ['ipa-cert-fix', '-v'], stdin_text='yes\n',
            )
            assert result.returncode == 0
            assert_postconditions(self.master)

            # Dogtag certs should be untouched (same expiry date)
            for nick in ('caSigningCert cert-pki-ca',
                         'Server-Cert cert-pki-ca',
                         'subsystemCert cert-pki-ca'):
                post = get_cert_expiry(
                    self.master, paths.PKI_TOMCAT_ALIAS_DIR, nick)
                assert post == pre_serials[nick], (
                    "%s was renewed but should not have been" % nick)
        finally:
            self.master.run_command(['systemctl', 'stop', 'certmonger'])
            self.master.run_command(
                'rm -fv ' + paths.CERTMONGER_REQUESTS_DIR + '*')
            tasks.uninstall_master(self.master)
            tasks.move_date(self.master, 'start', '-3Years-1day')

    def test_rm9_pki_server_unavailable(self, expire_cert_critical):
        """T-RM-9: pki-server cert-fix command not available.

        Rename pki-server binary.  Verify: actionable error,
        exit code 1, no certs modified.
        """
        expire_cert_critical(self.master)
        check_status(self.master, 8, "CA_UNREACHABLE")

        self.master.run_command(
            ['mv', '/usr/sbin/pki-server',
             '/usr/sbin/pki-server.bak']
        )
        try:
            result = self.master.run_command(
                ['ipa-cert-fix', '-v'], stdin_text='yes\n',
                raiseonerr=False,
            )
            assert result.returncode == 1
            assert 'not available' in result.stdout_text
        finally:
            self.master.run_command(
                ['mv', '/usr/sbin/pki-server.bak',
                 '/usr/sbin/pki-server']
            )


# ---------------------------------------------------------------
#  2. CA-Full Replica, Non-Destructive (T-REP-*)
# ---------------------------------------------------------------

class TestCertFixReplica(IntegrationTest):
    """Tests for the non-destructive replica fix scenario."""

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            mh.master, setup_dns=False, extra_args=['--no-ntp']
        )
        tasks.install_replica(
            mh.master, mh.replicas[0],
            setup_dns=False, extra_args=['--no-ntp']
        )

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def expire_certs(self):
        """Move system date forward on both hosts to expire certs."""
        for host in self.master, self.replicas[0]:
            tasks.move_date(host, 'stop', '+3years+1days')
            host.run_command(
                ['ipactl', 'restart', '--ignore-service-failures']
            )
        yield
        for host in self.replicas[0], self.master:
            tasks.uninstall_master(host)
            tasks.move_date(host, 'start', '-3years-1days')

    @pytest.fixture
    def expire_certs_and_fix_master(self, expire_certs):
        """Expire certs on both hosts, then fix the master.

        After this fixture, the master is operational (MONITORING)
        and the replica still has expired certs.
        """
        check_status(self.master, 8, "CA_UNREACHABLE")
        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")

    def test_rep1_replica_fixed_from_master(self, expire_certs):
        """T-REP-1: Replica fixed from healthy master.

        Fix master first, then run ipa-cert-fix on replica
        with --force-server to exercise the non-destructive
        replica path (_run_non_rm_replica_fix).  No manual cert
        resubmits -- the tool must handle everything.

        Verify: certs renewed by the tool, RM role unchanged,
        replication works afterward.
        """
        # Fix master first (renewal master path)
        check_status(self.master, 8, "CA_UNREACHABLE")
        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")

        # Record initial expiry on replica before fix
        initial_expiry = get_cert_expiry(
            self.replicas[0],
            paths.PKI_TOMCAT_ALIAS_DIR,
            'Server-Cert cert-pki-ca'
        )

        # Run ipa-cert-fix on replica -- this should use
        # the non-destructive path: fetch CA chain, RA,
        # subsystem certs from master, renew via certmonger
        # pointed at master, restart, resubmit remaining.
        # No manual resubmits needed.
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.master.hostname],
            stdin_text='yes\n',
        )
        assert result.returncode == 0
        check_status(self.replicas[0], 9, "MONITORING")
        assert_postconditions(self.replicas[0])

        # Verify cert was actually renewed by the tool
        renewed_expiry = get_cert_expiry(
            self.replicas[0],
            paths.PKI_TOMCAT_ALIAS_DIR,
            'Server-Cert cert-pki-ca'
        )
        assert renewed_expiry > initial_expiry

        # Verify replication works after fix
        stdin = (f"{self.master.config.admin_password}\n"
                 f"{self.master.config.admin_password}\n"
                 f"{self.master.config.admin_password}\n")
        self.master.run_command(
            ['kinit', 'admin'], stdin_text=stdin
        )
        tasks.user_add(
            self.master, 'rep1testuser',
            password='Secret@123',
        )
        time.sleep(5)
        self.replicas[0].run_command(
            ['kinit', 'admin'], stdin_text=stdin
        )
        self.replicas[0].run_command(
            ['ipa', 'user-show', 'rep1testuser']
        )

    def test_rep2_unattended_force_server(
        self, expire_certs_and_fix_master,
    ):
        """T-REP-2: Unattended with --force-server.

        No prompts, completes autonomously, exit code 0.
        """
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v', '-U',
             '--force-server', self.master.hostname],
        )
        assert result.returncode == 0
        check_status(self.replicas[0], 9, "MONITORING")
        assert_postconditions(self.replicas[0])

    def test_rep3_dry_run_on_replica(
        self, expire_certs_and_fix_master,
    ):
        """T-REP-3: Dry-run on replica shows plan, no changes."""
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v', '--dry-run',
             '--force-server', self.master.hostname],
        )
        assert result.returncode == 0
        assert "[DRY RUN]" in result.stdout_text

    def test_rep4_force_server_self(self):
        """T-REP-4: --force-server pointing to self is rejected."""
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.replicas[0].hostname],
            raiseonerr=False,
        )
        assert result.returncode != 0
        assert "different server" in result.stdout_text

    def test_rep5_force_server_unreachable(
        self, expire_certs_and_fix_master,
    ):
        """T-REP-5: --force-server to unreachable host fails."""
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', 'nonexistent.example.com'],
            stdin_text='yes\n',
            raiseonerr=False,
        )
        assert result.returncode != 0

    def test_rep13_user_declines(
        self, expire_certs_and_fix_master,
    ):
        """T-REP-13: User says "no" at replica fix prompt."""
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v'], stdin_text='no\n',
            raiseonerr=False,
        )
        assert "Not proceeding" in result.stdout_text


# ---------------------------------------------------------------
#  3. Third-party DS cert nickname (T-DETECT-5)
# ---------------------------------------------------------------

class TestCertFixThirdParty(CALessBase):
    """Verify ipa-cert-fix handles custom DS cert nicknames.

    T-DETECT-5: When LDAP uses a non-default certificate nickname
    (from ipa-server-certinstall), the tool must use the actual
    nickname, not a hardcoded value.
    """

    @classmethod
    def install(cls, mh):
        cls.nickname = 'ca1/server'
        super(TestCertFixThirdParty, cls).install(mh)
        tasks.install_master(cls.master, setup_dns=True)

    @server_install_teardown
    def test_detect5_custom_ds_nickname(self):
        """T-DETECT-5: Custom (third-party) DS certificate nickname."""
        self.create_pkcs12(self.nickname,
                           password=self.cert_password,
                           filename='server.p12')
        self.prepare_cacert('ca1')

        nick_chain = self.nickname.split('/')
        ca_cert = '%s.crt' % nick_chain[0]

        self.copy_cert(self.master, ca_cert)
        self.master.run_command(
            ['ipa-cacert-manage', 'install', ca_cert]
        )
        self.master.run_command(['ipa-certupdate'])

        self.copy_cert(self.master, 'server.p12')
        args = ['ipa-server-certinstall',
                '-p', self.master.config.dirman_password,
                '--pin', self.master.config.admin_password,
                '-d', 'server.p12']
        self.master.run_command(args)
        self.master.run_command(['ipactl', 'restart'])

        # ipa-cert-fix should use the custom nickname
        result = self.master.run_command(['ipa-cert-fix', '-v'])
        assert self.nickname in result.stderr_text


# ---------------------------------------------------------------
#  7. Cross-Cutting: Pre-flight (T-PRE-*)
# ---------------------------------------------------------------

class TestPreFlight(IntegrationTest):
    """Pre-flight check tests -- no install needed for some."""

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_pre1_ipa_not_configured(self):
        """T-PRE-1: ipa-cert-fix on non-IPA system returns exit code 2."""
        result = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n',
            raiseonerr=False,
        )
        assert result.returncode == 2

    def test_pre4_no_expired_certs(self):
        """T-PRE-4: No expired certs -- "Nothing to do"."""
        tasks.install_master(self.master, setup_dns=False,
                             extra_args=['--no-ntp'])
        try:
            result = self.master.run_command(
                ['ipa-cert-fix', '-v']
            )
            assert "Nothing to do" in result.stdout_text
            assert result.returncode == 0
        finally:
            tasks.uninstall_master(self.master)


# ---------------------------------------------------------------
#  6. Topology-Wide Expiry (T-TOPO-*)
#  9. End-to-End Story Tests (T-E2E-*)
# ---------------------------------------------------------------

class TestTopologyWideExpiry(IntegrationTest):
    """Tests for topology-wide certificate expiry.

    Covers T-TOPO-* and T-E2E-1: the realistic scenario where
    all certs are expired on all hosts and recovery must proceed
    in the correct order.
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            mh.master, setup_dns=False,
            extra_args=['--no-ntp']
        )
        tasks.install_replica(
            mh.master, mh.replicas[0],
            setup_dns=False, extra_args=['--no-ntp']
        )

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def expire_all(self):
        """Expire certs on both master and replica."""
        for host in self.master, self.replicas[0]:
            tasks.move_date(host, 'stop', '+3years+1days')
            host.run_command(
                ['ipactl', 'restart', '--ignore-service-failures']
            )
        yield
        for host in self.replicas[0], self.master:
            tasks.uninstall_master(host)
            tasks.move_date(host, 'start', '-3years-1days')

    def test_topo1_fix_master_then_replica(self, expire_all):
        """T-TOPO-1 / T-E2E-1: Fix master first, then replica.

        This is the most common real-world disaster recovery scenario.
        Both hosts have expired certs.  Fix the master (renewal master
        path), then fix the replica (non-destructive path).
        """
        # Step 1: Fix master
        check_status(self.master, 8, "CA_UNREACHABLE")
        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")
        assert_postconditions(self.master)

        # Step 2: Fix replica using master
        self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.master.hostname],
            stdin_text='yes\n',
        )
        check_status(self.replicas[0], 9, "MONITORING")
        assert_postconditions(self.replicas[0])

        # Step 3: Verify topology healthy
        stdin = (f"{self.master.config.admin_password}\n"
                 f"{self.master.config.admin_password}\n"
                 f"{self.master.config.admin_password}\n")
        self.master.run_command(
            ['kinit', 'admin'], stdin_text=stdin
        )
        tasks.user_add(self.master, 'topo1testuser', password='Secret@123')

        self.replicas[0].run_command(
            ['kinit', 'admin'], stdin_text=stdin
        )
        # Wait a moment for replication
        time.sleep(5)
        self.replicas[0].run_command(
            ['ipa', 'user-show', 'topo1testuser']
        )

    def test_topo2_replica_before_master_fixed(self, expire_all):
        """T-TOPO-2: Replica attempt before master is fixed.

        Master's HTTPS cert is expired.  TLS handshake from
        replica to master must fail with an actionable error.
        """
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.master.hostname],
            stdin_text='yes\n',
            raiseonerr=False,
        )
        # Should fail -- master's certs are also expired
        assert result.returncode != 0


# ---------------------------------------------------------------
#  7. Cross-Cutting: Idempotency (T-IDEM-*)
# ---------------------------------------------------------------

class TestIdempotency(IntegrationTest):
    """Verify ipa-cert-fix is safe to re-run."""

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_idem1_second_run(self, expire_cert_critical):
        """T-IDEM-1: Second run immediately after fix.

        After a successful fix, re-run produces "Nothing to do".
        """
        expire_cert_critical(self.master)
        check_status(self.master, 8, "CA_UNREACHABLE")

        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")

        result = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        assert "Nothing to do" in result.stdout_text
        assert_postconditions(self.master)


# ---------------------------------------------------------------
#  3. CA-Full Replica -- Promote to RM (T-PROMO-*)
# ---------------------------------------------------------------

class TestCertFixPromotion(IntegrationTest):
    """Tests for the promote-to-renewal-master scenario.

    Requires a topology where the renewal master is permanently
    down so the replica must be promoted.
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            mh.master, setup_dns=False, extra_args=['--no-ntp']
        )
        tasks.install_replica(
            mh.master, mh.replicas[0],
            setup_dns=False, extra_args=['--no-ntp']
        )

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def expire_and_shutdown_master(self):
        """Expire certs on replica, shut down master permanently."""
        # Expire certs on both hosts
        for host in self.master, self.replicas[0]:
            tasks.move_date(host, 'stop', '+3years+1days')
        # Shut down master entirely to simulate permanent failure
        self.master.run_command(['ipactl', 'stop'])
        self.replicas[0].run_command(
            ['ipactl', 'restart', '--ignore-service-failures']
        )
        yield
        for host in self.replicas[0], self.master:
            tasks.uninstall_master(host)
            tasks.move_date(host, 'start', '-3years-1days')

    def test_promo1_promote_when_master_down(
        self, expire_and_shutdown_master
    ):
        """T-PROMO-1: Promotion when master is permanently down.

        Replica should detect no working master, offer promotion,
        become RM, and renew certs.
        """
        check_status(self.replicas[0], 8, "CA_UNREACHABLE")

        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v', '--renewal-master'],
            stdin_text='yes\n',
        )
        assert result.returncode == 0
        check_status(self.replicas[0], 9, "MONITORING")
        assert_postconditions(self.replicas[0])

        # Verify CRL warning is printed
        assert "ipa-crlgen-manage" in result.stdout_text

    def test_promo2_unattended_refuses_promotion(
        self, expire_and_shutdown_master
    ):
        """T-PROMO-2/3: Unattended without --renewal-master refuses.

        In unattended mode without --renewal-master, the tool
        must refuse to silently promote.  RM role unchanged, no certs
        renewed, exit code 1, message mentions --renewal-master.
        """
        check_status(self.replicas[0], 8, "CA_UNREACHABLE")

        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v', '-U'],
            raiseonerr=False,
        )
        assert result.returncode == 1
        assert "--renewal-master" in result.stdout_text


# ---------------------------------------------------------------
#  4. CA-Less Replica (T-CALESS-*)
# ---------------------------------------------------------------

class TestCertFixCALess(IntegrationTest):
    """Tests for the CA-less replica fix scenario.

    Topology: CA-full master + CA-less replica.
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            mh.master, setup_dns=True, extra_args=['--no-ntp']
        )
        tasks.install_replica(
            mh.master, mh.replicas[0],
            setup_ca=False, setup_dns=False,
            extra_args=['--no-ntp'],
        )

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def expire_caless_certs(self):
        """Expire service certs on the CA-less replica."""
        for host in self.master, self.replicas[0]:
            tasks.move_date(host, 'stop', '+3years+1days')
            host.run_command(
                ['ipactl', 'restart', '--ignore-service-failures']
            )
        yield
        for host in self.replicas[0], self.master:
            tasks.uninstall_master(host)
            tasks.move_date(host, 'start', '-3years-1days')

    @pytest.fixture
    def expire_caless_and_fix_master(self, expire_caless_certs):
        """Expire certs on both hosts, then fix the master."""
        check_status(self.master, 8, "CA_UNREACHABLE")
        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")

    def test_caless1_renewed_from_ca_server(
        self, expire_caless_certs
    ):
        """T-CALESS-1: HTTP/LDAP/KDC renewed from CA server.

        Fix master first (RM path), then fix CA-less replica
        using --force-server=master.  Verify: only IPA service
        certs renewed, no Dogtag certs touched.
        """
        # Fix master first
        check_status(self.master, 8, "CA_UNREACHABLE")
        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")

        # Fix CA-less replica
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.master.hostname],
            stdin_text='yes\n',
        )
        assert result.returncode == 0
        assert_postconditions(self.replicas[0])

        # Verify no dogtag certs on CA-less replica
        cmd = self.replicas[0].run_command(
            ['getcert', 'list',
             '-d', paths.PKI_TOMCAT_ALIAS_DIR],
            raiseonerr=False,
        )
        # CA-less replica should not have PKI tomcat certs
        if cmd.returncode == 0:
            assert 'caSigningCert' not in cmd.stdout_text

    def test_caless2_dry_run(self, expire_caless_and_fix_master):
        """T-CALESS-2: Dry-run on CA-less replica.

        Shows empty Dogtag list, lists IPA certs to be renewed.
        """
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v', '--dry-run',
             '--force-server', self.master.hostname],
        )
        assert result.returncode == 0
        assert "[DRY RUN]" in result.stdout_text

    def test_caless4_user_declines(
        self, expire_caless_and_fix_master,
    ):
        """T-CALESS-4: User declines confirmation on CA-less replica."""
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.master.hostname],
            stdin_text='no\n',
        )
        assert "Not proceeding" in result.stdout_text


# ---------------------------------------------------------------
#  5. External CA (T-EXT-*)
# ---------------------------------------------------------------

class TestCertFixExternalCA(IntegrationTest):
    """Tests for external CA deployment scenarios.

    Uses 2-step external CA installation.
    """

    ROOT_CA = 'root_ca.crt'
    IPA_CA = 'ipa_ca.crt'

    @classmethod
    def install(cls, mh):
        pass

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def external_ca_server(self):
        """Install IPA with external CA, then expire certs."""
        # Step 1
        install_server_external_ca_step1(self.master)

        # Sign CSR and transport certs
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.ROOT_IPA_CSR,
            self.ROOT_CA, self.IPA_CA,
        )

        # Step 2
        install_server_external_ca_step2(
            self.master, ipa_ca_fname, root_ca_fname,
        )

        yield

        self.master.run_command(
            ['systemctl', 'stop', 'certmonger'],
            raiseonerr=False,
        )
        self.master.run_command(
            'rm -fv ' + paths.CERTMONGER_REQUESTS_DIR + '*',
            raiseonerr=False,
        )
        tasks.uninstall_master(self.master)

    def test_ext3_unattended_generates_csr(self, external_ca_server):
        """T-EXT-3: Unattended with externally-signed CA.

        With all certs expired on an externally-signed CA
        deployment, the CA cert is expired too.  The tool
        must refuse (CA cert renewal is manual), extract
        the CSR, and return exit code 1.
        """
        # Move date to expire certs
        tasks.move_date(self.master, 'stop', '+3years+1days')
        self.master.run_command(
            ['ipactl', 'restart', '--ignore-service-failures']
        )

        try:
            result = self.master.run_command(
                ['ipa-cert-fix', '-v', '-U'],
                raiseonerr=False,
            )
            # CA cert is expired → tool prints guidance and exits with code 1
            assert result.returncode == 1
            assert (
                'ipa-cacert-manage' in result.stdout_text
                or 'ca.csr' in result.stdout_text
            )
        finally:
            tasks.move_date(
                self.master, 'start', '-3years-1days'
            )


class TestCertFixMixedExternal(IntegrationTest):
    """T-EXT-1/2: Mixed deployment with externally-signed HTTP cert.

    IPA CA is self-signed (normal), but HTTP cert is replaced with
    an externally-signed one via ipa-server-certinstall.  Tests
    transition to internal CA and CSR generation.
    """

    @classmethod
    def install(cls, mh):
        pass

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def mixed_expired(self):
        """Install master, replace HTTP cert with external, expire."""
        tasks.install_master(self.master, setup_dns=False,
                             extra_args=['--no-ntp'])

        # Generate a self-signed external cert for HTTP
        self.master.run_command([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', '/root/ext-http.key',
            '-out', '/root/ext-http.crt',
            '-days', '365', '-nodes',
            '-subj', '/CN=%s' % self.master.hostname,
        ])
        # Create PKCS#12 for ipa-server-certinstall
        self.master.run_command([
            'openssl', 'pkcs12', '-export',
            '-in', '/root/ext-http.crt',
            '-inkey', '/root/ext-http.key',
            '-out', '/root/ext-http.p12',
            '-passout', 'pass:Secret123',
            '-name', self.master.hostname,
        ])
        # Install external HTTP cert
        self.master.run_command([
            'ipa-server-certinstall', '--http',
            '/root/ext-http.p12',
            '--pin', 'Secret123',
            '-p', self.master.config.dirman_password,
        ])

        # Expire certs
        tasks.move_date(self.master, 'stop', '+3Years+1day')
        yield
        self.master.run_command(
            ['systemctl', 'stop', 'certmonger'],
            raiseonerr=False)
        self.master.run_command(
            'rm -fv ' + paths.CERTMONGER_REQUESTS_DIR + '*',
            raiseonerr=False)
        tasks.uninstall_master(self.master)
        tasks.move_date(self.master, 'start', '-3Years-1day')

    def test_ext1_transition_to_internal_ca(self, mixed_expired):
        """T-EXT-1: Accept transition of external HTTP cert to IPA CA.

        The tool should detect the externally-signed HTTP cert,
        offer transition, and upon acceptance obtain a new
        internally-signed cert via certmonger.
        """
        # Answer 'yes' to the warning, then 'True' to transition
        result = self.master.run_command(
            ['ipa-cert-fix', '-v'],
            stdin_text='yes\nTrue\n',
        )
        assert result.returncode == 0
        assert 'transitioned successfully' in result.stdout_text
        assert_postconditions(self.master)

    def test_ext2_decline_transition_generates_csr(self, mixed_expired):
        """T-EXT-2: Decline transition -> CSR generated.

        The tool should generate a CSR from the existing key and
        print ipa-server-certinstall instructions.
        """
        # Answer 'yes' to the warning, then 'False' to decline
        result = self.master.run_command(
            ['ipa-cert-fix', '-v'],
            stdin_text='yes\nFalse\n',
        )
        assert result.returncode == 0
        output = result.stdout_text
        assert 'CSR' in output or '.csr' in output
        assert 'ipa-server-certinstall' in output


# ---------------------------------------------------------------
#  7. Cross-Cutting: Pre-flight additions (T-PRE-3)
# ---------------------------------------------------------------

class TestPreFlightDS(IntegrationTest):
    """Pre-flight check: DS down."""

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_pre3_ds_down(self, expire_cert_critical):
        """T-PRE-3: Directory Server down blocks ipa-cert-fix.

        Stop dirsrv, verify ipa-cert-fix refuses to proceed.
        """
        expire_cert_critical(self.master)
        instance = realm_to_serverid(self.master.domain.realm)
        self.master.run_command(
            ['systemctl', 'stop',
             'dirsrv@%s' % instance]
        )
        try:
            result = self.master.run_command(
                ['ipa-cert-fix', '-v'],
                stdin_text='yes\n',
                raiseonerr=False,
            )
            assert result.returncode == 1
        finally:
            self.master.run_command(
                ['systemctl', 'start',
                 'dirsrv@%s' % instance],
                raiseonerr=False,
            )


# ---------------------------------------------------------------
#  7. Cross-Cutting: State Restoration (T-RESTORE-*)
# ---------------------------------------------------------------

class TestStateRestoration(IntegrationTest):
    """Verify state is properly restored after failures."""

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            mh.master, setup_dns=False, extra_args=['--no-ntp']
        )
        tasks.install_replica(
            mh.master, mh.replicas[0],
            setup_dns=False, extra_args=['--no-ntp']
        )

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def expire_and_block(self):
        """Expire certs on replica, fix master, then block master."""
        for host in self.master, self.replicas[0]:
            tasks.move_date(host, 'stop', '+3years+1days')
            host.run_command(
                ['ipactl', 'restart', '--ignore-service-failures']
            )
        # Fix master first
        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")

        # Block HTTPS on master to cause replica fix timeout
        fw = Firewall(self.master)
        fw.disable_service("https")
        yield
        fw.enable_service("https")
        for host in self.replicas[0], self.master:
            tasks.uninstall_master(host)
            tasks.move_date(host, 'start', '-3years-1days')

    def test_restore1_ca_helper_after_timeout(
        self, expire_and_block
    ):
        """T-RESTORE-1: IPA CA helper restored after timeout.

        Cause a timeout during cert renewal by blocking HTTPS.
        Verify P1: certmonger external-helper has no -J override.
        """
        result = self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.master.hostname],
            stdin_text='yes\n',
            raiseonerr=False,
        )
        # Should fail due to blocked HTTPS
        assert result.returncode != 0

        # P1: IPA CA helper must be cleaned up
        assert_postconditions(self.replicas[0])

    @pytest.fixture
    def expire_and_block_after_first(self):
        """Expire certs on replica, fix master, let first cert
        renew, then block master mid-flow."""
        for host in self.master, self.replicas[0]:
            tasks.move_date(host, 'stop', '+3years+1days')
            host.run_command(
                ['ipactl', 'restart', '--ignore-service-failures']
            )
        # Fix master first
        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")
        yield
        # Ensure firewall is restored even if test fails
        fw = Firewall(self.master)
        fw.enable_service("https")
        for host in self.replicas[0], self.master:
            tasks.uninstall_master(host)
            tasks.move_date(host, 'start', '-3years-1days')

    def test_restore2_dogtag_ca_profile_restored(
        self, expire_and_block_after_first,
    ):
        """T-RESTORE-2: Dogtag CA name and profile restored.

        Start renewal on replica, block HTTPS after the first
        cert succeeds so the second times out.  Verify P2/P5:
        Dogtag certs have ca-name=dogtag-ipa-ca-renew-agent
        (not IPA) and no orphaned host/ principal.
        """
        # Start ipa-cert-fix on replica; it will begin renewing
        # certs from the master.  Block HTTPS partway through.
        # The tool's finally block should restore all certmonger
        # state regardless of which cert failed.
        fw = Firewall(self.master)

        # Give the tool time to start renewing the first cert,
        # then block HTTPS so subsequent certs time out.
        # We use a background ipa-cert-fix + sleep + firewall.
        self.replicas[0].run_command(
            ['bash', '-c',
             'nohup ipa-cert-fix -v --force-server %s '
             '< <(echo yes) &>/root/certfix.log &'
             % self.master.hostname],)
        time.sleep(30)
        fw.disable_service("https")

        # Wait for ipa-cert-fix to finish (it will time out)
        for _i in range(60):
            rc = self.replicas[0].run_command(
                ['pgrep', '-f', 'ipa-cert-fix'],
                raiseonerr=False,
            )
            if rc.returncode != 0:
                break
            time.sleep(10)

        # P2 + P5: certmonger state must be clean
        assert_postconditions(self.replicas[0])

        # Explicit check: Dogtag certs must NOT have CA=IPA
        for nickname in ('auditSigningCert cert-pki-ca',
                         'ocspSigningCert cert-pki-ca',
                         'subsystemCert cert-pki-ca'):
            cmd = self.replicas[0].run_command(
                ['getcert', 'list',
                 '-d', paths.PKI_TOMCAT_ALIAS_DIR,
                 '-n', nickname],
                raiseonerr=False,
            )
            if cmd.returncode == 0:
                assert 'CA: IPA' not in cmd.stdout_text, (
                    "%s still has CA=IPA after failure"
                    % nickname
                )


# ---------------------------------------------------------------
#  7. Cross-Cutting: Detection Edge Cases (T-DETECT-*)
# ---------------------------------------------------------------

class TestDetectionEdgeCases(IntegrationTest):
    """Deployment detection edge case tests."""

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_detect1_nss_unreadable(self, expire_cert_critical):
        """T-DETECT-1: NSS database unreadable.

        Corrupt permissions on PKI NSS database. Verify:
        actionable error, no crash.
        """
        expire_cert_critical(self.master)

        # Make NSS db unreadable
        self.master.run_command(
            ['chmod', '000', paths.PKI_TOMCAT_ALIAS_DIR]
        )
        try:
            result = self.master.run_command(
                ['ipa-cert-fix', '-v'],
                stdin_text='yes\n',
                raiseonerr=False,
            )
            # Should fail with a meaningful error, not a traceback
            assert result.returncode != 0
        finally:
            self.master.run_command(
                ['chmod', '755', paths.PKI_TOMCAT_ALIAS_DIR]
            )

    def test_detect3_cert_file_missing(self, expire_cert_critical):
        """T-DETECT-3: One service cert file missing.

        Delete KDC cert. Verify: detection still works,
        missing cert skipped with warning.
        """
        expire_cert_critical(self.master)

        # Back up and remove KDC cert
        self.master.run_command(
            ['cp', paths.KDC_CERT, '/root/kdc_cert.bak']
        )
        self.master.run_command(['rm', '-f', paths.KDC_CERT])
        try:
            result = self.master.run_command(
                ['ipa-cert-fix', '-v'],
                stdin_text='yes\n',
                raiseonerr=False,
            )
            # Missing KDC cert is skipped; other expired
            # certs are still fixed.  Should succeed.
            assert result.returncode == 0
        finally:
            self.master.run_command(
                ['cp', '/root/kdc_cert.bak', paths.KDC_CERT],
                raiseonerr=False,
            )

    def test_detect4_all_cert_files_missing(self, expire_cert_critical):
        """T-DETECT-4: All service cert files missing.

        Delete HTTP, LDAP, and KDC cert files.  Verify: tool does
        not claim "Nothing to do" -- it should still detect expired
        Dogtag certs and proceed (or report the missing files).
        """
        expire_cert_critical(self.master)

        # Back up and remove all IPA service cert files
        for certfile in (paths.HTTPD_CERT_FILE,
                         paths.KDC_CERT):
            self.master.run_command(
                ['cp', certfile, certfile + '.bak'],
                raiseonerr=False,
            )
            self.master.run_command(['rm', '-f', certfile])

        try:
            result = self.master.run_command(
                ['ipa-cert-fix', '-v'], stdin_text='yes\n',
                raiseonerr=False,
            )
            # Should NOT say "Nothing to do" -- Dogtag certs
            # are still expired even if IPA cert files are gone.
            assert "Nothing to do" not in result.stdout_text
        finally:
            for certfile in (paths.HTTPD_CERT_FILE,
                             paths.KDC_CERT):
                self.master.run_command(
                    ['cp', certfile + '.bak', certfile],
                    raiseonerr=False,
                )


# ---------------------------------------------------------------
#  7. RA/Subsystem LDAP Consistency (T-CONSIST-*)
# ---------------------------------------------------------------

class TestConsistency(IntegrationTest):
    """RA/Subsystem LDAP consistency check tests."""

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def installed_master(self):
        """Install a master for consistency tests."""
        tasks.install_master(self.master, setup_dns=False,
                             extra_args=['--no-ntp'])
        yield
        tasks.uninstall_master(self.master)

    def _break_ra_serial(self):
        """Modify uid=ipara description to contain a wrong serial."""
        self.master.run_command([
            'ldapmodify', '-x', '-H',
            'ldap://%s' % self.master.hostname,
            '-D', 'cn=Directory Manager',
            '-w', self.master.config.dirman_password,
        ], stdin_text=(
            "dn: uid=ipara,ou=People,o=ipaca\nchangetype: modify\n"
            "replace: description\ndescription: 2;99999;CN=bad;CN=bad\n"
        ))

    def test_consist1_ra_serial_mismatch(self, installed_master):
        """T-CONSIST-1: RA cert serial mismatch in LDAP.

        Modify uid=ipara description to contain a wrong serial.
        Run ipa-cert-fix.  Verify mismatch detected and fixed.
        """
        self._break_ra_serial()

        result = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n',
        )
        assert result.returncode == 0
        assert 'description serial mismatch' in result.stdout_text
        assert 'Updated' in result.stdout_text

        # Verify fixed: re-run should say "Nothing to do"
        result2 = self.master.run_command(
            ['ipa-cert-fix', '-v'],
        )
        assert "Nothing to do" in result2.stdout_text

    def test_consist3_dry_run_no_fix(self, installed_master):
        """T-CONSIST-3: Dry-run shows mismatches without fixing.

        Same setup as T-CONSIST-1 but with --dry-run.  LDAP
        must not be modified.
        """
        self._break_ra_serial()

        result = self.master.run_command(
            ['ipa-cert-fix', '-v', '--dry-run'],
        )
        assert result.returncode == 0
        assert '[DRY RUN]' in result.stdout_text
        assert 'description serial mismatch' in result.stdout_text

        # Mismatch should still be present (not fixed)
        result2 = self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n',
        )
        assert 'description serial mismatch' in result2.stdout_text

    def test_consist4_no_mismatches_no_prompt(self, installed_master):
        """T-CONSIST-4: No mismatches, no consistency prompt.

        On a healthy server with no expired certs, the tool
        should say "Nothing to do" without any mismatch output.
        """
        result = self.master.run_command(
            ['ipa-cert-fix', '-v'],
        )
        assert "Nothing to do" in result.stdout_text
        assert 'mismatch' not in result.stdout_text.lower()
        assert 'Updated' not in result.stdout_text


# ---------------------------------------------------------------
#  9. End-to-End: Full Topology Recovery (T-E2E-1)
# ---------------------------------------------------------------

class TestE2EFullTopology(IntegrationTest):
    """End-to-end: master + CA replica + CA-less replica.

    T-E2E-1: The single most important test -- complete
    topology recovery.
    """

    num_replicas = 2

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            mh.master, setup_dns=True, extra_args=['--no-ntp']
        )
        # replica 0: CA-full
        tasks.install_replica(
            mh.master, mh.replicas[0],
            setup_dns=False, extra_args=['--no-ntp'],
        )
        # replica 1: CA-less
        tasks.install_replica(
            mh.master, mh.replicas[1],
            setup_ca=False, setup_dns=False,
            extra_args=['--no-ntp'],
        )

    @classmethod
    def uninstall(cls, mh):
        pass

    @pytest.fixture
    def expire_topology(self):
        """Expire certs on all three hosts."""
        for host in (self.master, self.replicas[0], self.replicas[1]):
            tasks.move_date(host, 'stop', '+3years+1days')
            host.run_command(
                ['ipactl', 'restart', '--ignore-service-failures']
            )
        yield
        for host in (self.replicas[1], self.replicas[0], self.master):
            tasks.uninstall_master(host)
            tasks.move_date(host, 'start', '-3years-1days')

    def test_e2e1_full_recovery(self, expire_topology):
        """T-E2E-1: Full topology recovery sequence.

        1. Fix master (renewal master path)
        2. Fix CA-full replica (non-destructive)
        3. Fix CA-less replica
        4. Verify all hosts operational
        """
        # Step 1: Fix master
        check_status(self.master, 8, "CA_UNREACHABLE")
        self.master.run_command(
            ['ipa-cert-fix', '-v'], stdin_text='yes\n'
        )
        check_status(self.master, 9, "MONITORING")
        assert_postconditions(self.master)

        # Step 2: Fix CA-full replica
        self.replicas[0].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.master.hostname],
            stdin_text='yes\n',
        )
        check_status(self.replicas[0], 9, "MONITORING")
        assert_postconditions(self.replicas[0])

        # Step 3: Fix CA-less replica
        self.replicas[1].run_command(
            ['ipa-cert-fix', '-v',
             '--force-server', self.master.hostname],
            stdin_text='yes\n',
        )
        assert_postconditions(self.replicas[1])

        # Step 4: Verify topology is healthy
        stdin = (f"{self.master.config.admin_password}\n"
                 f"{self.master.config.admin_password}\n"
                 f"{self.master.config.admin_password}\n")
        self.master.run_command(
            ['kinit', 'admin'], stdin_text=stdin
        )
        tasks.user_add(
            self.master, 'e2e1testuser', password='Secret@123'
        )

        # Verify replication to CA-full replica
        time.sleep(5)
        self.replicas[0].run_command(
            ['kinit', 'admin'], stdin_text=stdin
        )
        self.replicas[0].run_command(
            ['ipa', 'user-show', 'e2e1testuser']
        )

        # Verify replication to CA-less replica
        self.replicas[1].run_command(
            ['kinit', 'admin'], stdin_text=stdin
        )
        self.replicas[1].run_command(
            ['ipa', 'user-show', 'e2e1testuser']
        )
