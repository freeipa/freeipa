#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Unit tests for ipa-cert-fix.

These tests use mocks and do not require an IPA deployment.
They exercise pure logic and should run in seconds.
"""
from unittest import mock
import pytest

from ipaserver.install.ipa_cert_fix import (
    CertIdentity,
    CertmongerClient,
    DeploymentDetector,
    DeploymentType,
    DOGTAG_CERTS,
    ExternalCertHandler,
    FixScenario,
    IPACertType,
    _check_tcp_reachable,
)

MODULE = 'ipaserver.install.ipa_cert_fix'
SMOD = 'ipaserver.install.ipa_cert_fix_services'


class TestUnitKDCCertClassification:
    """T-UNIT-1: KDC cert classified as KDC, not HTTPS."""

    @mock.patch(SMOD + '.is_ipa_issued_cert', return_value=False)
    @mock.patch(SMOD + '.x509.load_certificate_from_file')
    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.dsinstance')
    @mock.patch(SMOD + '.realm_to_serverid',
                return_value='EXAMPLE-COM')
    @mock.patch(SMOD + '.api')
    def test_kdc_not_tagged_as_https(
        self, mock_api, mock_r2s, mock_ds, mock_nssdb,
        mock_load_cert, mock_is_ipa,
    ):
        """Non-IPA-issued KDC cert must appear in non_renewed
        as IPACertType.KDC, not IPACertType.HTTPS.

        Regression test for a bug where the KDC entry in
        expired_ipa_certs() was incorrectly tagged HTTPS.
        """
        from ipaserver.install.ipa_cert_fix import (
            expired_ipa_certs,
        )

        import datetime as dt
        now = dt.datetime(
            2030, 1, 1, tzinfo=dt.timezone.utc
        )
        expired = dt.datetime(
            2029, 6, 1, tzinfo=dt.timezone.utc
        )

        # All certs expired
        cert_mock = mock.MagicMock()
        cert_mock.not_valid_after_utc = expired
        mock_load_cert.return_value = cert_mock

        # LDAP cert via NSSDatabase
        db_instance = mock.MagicMock()
        db_instance.get_cert.return_value = cert_mock
        mock_nssdb.return_value = db_instance

        # dsinstance setup
        ds_instance = mock.MagicMock()
        ds_instance.get_server_cert_nickname.return_value = ('Server-Cert')
        mock_ds.DsInstance.return_value = ds_instance
        mock_ds.config_dirname.return_value = '/etc/dirsrv/slapd-X'
        mock_api.env.realm = 'EXAMPLE.COM'

        # is_ipa_issued_cert returns False for HTTPS, LDAP, KDC
        # (RA is always added without the IPA-issued check)
        certs, non_renewed = expired_ipa_certs(now)

        # RA is always IPA-issued, so it goes to certs
        assert any(
            t == IPACertType.IPARA for t, _c in certs
        )

        # HTTPS, LDAPS, KDC are externally signed -> non_renewed
        non_renewed_types = [t for t, _c in non_renewed]
        assert IPACertType.HTTPS in non_renewed_types
        assert IPACertType.LDAPS in non_renewed_types
        assert IPACertType.KDC in non_renewed_types

        # The bug: KDC was tagged as HTTPS.  Verify no duplicate HTTPS entries.
        https_count = non_renewed_types.count(IPACertType.HTTPS)
        assert https_count == 1, (
            "KDC cert misclassified as HTTPS "
            "(got %d HTTPS entries)" % https_count
        )


class TestUnitPrincipalRestore:
    """T-UNIT-2: Principal save/restore behavior."""

    def test_original_principals_restored(self):
        """_restore restores saved principals."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        obj = CertRenewalFromMaster(mock.MagicMock(), 'master')
        obj._original_principals = {
            '123': ['dogtag-ipa-ca-renew-agent'],
        }
        obj._original_profiles = {}

        obj._cm.get_request_value.return_value = 'IPA'

        obj._restore('123', 'dogtag-ipa-ca-renew-agent')

        # Should restore the saved principal
        obj._cm.add_request_value.assert_called_once_with(
            '123', 'template-principal',
            ['dogtag-ipa-ca-renew-agent'])

    def test_empty_principals_skipped(self):
        """No principal restore when original was empty."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        obj = CertRenewalFromMaster(mock.MagicMock(), 'master')
        obj._original_principals = {'123': None}
        obj._original_profiles = {}

        obj._cm.get_request_value.return_value = 'IPA'

        obj._restore('123', 'dogtag-ipa-ca-renew-agent')

        # Should NOT call add_request_value for principals
        obj._cm.add_request_value.assert_not_called()


class TestUnitScenarioRouting:
    """T-UNIT-3: Scenario routing for each deployment type."""

    def _make_detector(self, is_rm, master, force_rm=False):
        """Create a mock DeploymentDetector with controlled state."""
        options = mock.MagicMock()
        options.renewal_master = force_rm
        options.force_server = None
        options.unattended = False
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=options,
        )
        obj.check_is_renewal_master = mock.MagicMock(
            return_value=is_rm
        )
        obj.get_master_server = mock.MagicMock(
            return_value=master
        )
        return obj

    @pytest.mark.parametrize(
        "dt,is_rm,master,expected_scenario", [
            (DeploymentType.CA_SELF_SIGNED,
             True, None,
             FixScenario.RENEWAL_MASTER),
            (DeploymentType.CA_SELF_SIGNED,
             False, 'master.example.com',
             FixScenario.CA_FULL_WITH_MASTER),
            (DeploymentType.CA_SELF_SIGNED,
             False, None,
             FixScenario.CA_FULL_PROMOTE),
            (DeploymentType.CA_EXTERNALLY_SIGNED,
             True, None,
             FixScenario.RENEWAL_MASTER),
            (DeploymentType.CA_EXTERNALLY_SIGNED,
             False, 'master.example.com',
             FixScenario.CA_FULL_WITH_MASTER),
            (DeploymentType.CA_LESS,
             False, 'master.example.com',
             FixScenario.CA_LESS_WITH_MASTER),
            (DeploymentType.CA_LESS_EXTERNAL,
             False, None,
             FixScenario.EXTERNAL_CERTS),
        ],
    )
    def test_scenario_matrix(
        self, dt, is_rm, master, expected_scenario
    ):
        """Verify correct FixScenario for each combination."""
        obj = self._make_detector(is_rm, master)
        scenario, srv = obj.determine_scenario(dt)
        assert scenario == expected_scenario
        if expected_scenario in (
            FixScenario.CA_FULL_WITH_MASTER,
            FixScenario.CA_LESS_WITH_MASTER,
        ):
            assert srv == master
        elif expected_scenario in (
            FixScenario.RENEWAL_MASTER,
            FixScenario.CA_FULL_PROMOTE,
            FixScenario.EXTERNAL_CERTS,
        ):
            assert srv is None

    def test_caless_no_server_raises(self):
        """CA_LESS with no server selected raises RuntimeError."""
        obj = self._make_detector(is_rm=False, master=None)
        with pytest.raises(RuntimeError, match="No server"):
            obj.determine_scenario(DeploymentType.CA_LESS)

    def test_force_renewal_master_flag(self):
        """--renewal-master forces RENEWAL_MASTER scenario."""
        obj = self._make_detector(
            is_rm=False, master='m.example.com',
            force_rm=True,
        )
        scenario, srv = obj.determine_scenario(
            DeploymentType.CA_SELF_SIGNED
        )
        assert scenario == FixScenario.RENEWAL_MASTER
        assert srv is None


class TestUnitCertClassification:
    """T-UNIT-4: Cert classification splits external from IPA."""

    @mock.patch(SMOD + '.cainstance')
    @mock.patch(SMOD + '.expired_dogtag_certs')
    @mock.patch(SMOD + '.expired_ipa_certs')
    def test_external_certs_split(
        self, mock_exp_ipa, mock_exp_dog, mock_ca,
    ):
        """Verify _classify_certs moves non_renewed to external."""
        import datetime as dt
        now = dt.datetime(
            2030, 1, 1, tzinfo=dt.timezone.utc
        )

        mock_ca.is_ca_installed_locally.return_value = True

        cert_mock = mock.MagicMock()
        mock_exp_dog.return_value = [('ca_audit', cert_mock)]
        mock_exp_ipa.return_value = (
            [(IPACertType.IPARA, cert_mock)],
            [(IPACertType.HTTPS, cert_mock)],  # non_renewed
        )

        dogtag, ipa, external = DeploymentDetector._classify_certs(now)

        assert len(dogtag) == 1
        assert len(ipa) == 1
        assert len(external) == 1
        assert external[0][0] == IPACertType.HTTPS

    @mock.patch(SMOD + '.cainstance')
    @mock.patch(SMOD + '.expired_ipa_certs')
    def test_caless_skips_dogtag(
        self, mock_exp_ipa, mock_ca,
    ):
        """On CA-less, dogtag certs list is empty."""
        import datetime as dt
        now = dt.datetime(
            2030, 1, 1, tzinfo=dt.timezone.utc
        )

        mock_ca.is_ca_installed_locally.return_value = False

        cert_mock = mock.MagicMock()
        mock_exp_ipa.return_value = (
            [(IPACertType.HTTPS, cert_mock)],
            [],
        )

        dogtag, ipa, _external = DeploymentDetector._classify_certs(now)

        assert dogtag == []
        assert len(ipa) == 1


class TestUnitForceServerSelf:
    """T-UNIT-5: --force-server=self rejected early in run()."""

    @mock.patch(MODULE + '.is_ipa_configured', return_value=True)
    @mock.patch(MODULE + '.api')
    def test_force_server_self_rejected(self, mock_api, _mock_cfg):
        """run() returns 1 when --force-server points to self."""
        from ipaserver.install.ipa_cert_fix import IPACertFix

        mock_api.env.host = 'replica.example.com'
        mock_api.bootstrap = mock.MagicMock()
        mock_api.finalize = mock.MagicMock()

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.force_server = 'replica.example.com'

        result = obj.run()
        assert result == 1


class TestUnitDryRunExitCode:
    """T-UNIT-6: Dry-run returns 0 for each scenario."""

    def _make_certfix_with_dry_run(self):
        """Create a mock IPACertFix with dry_run=True."""
        from ipaserver.install.ipa_cert_fix import (
            IPACertFix, CertFixContext,
        )

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = True
        obj.options.unattended = False
        obj.options.verbose = False

        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.RENEWAL_MASTER,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[],
            ipa_certs=[],

            external_certs=[],
            master_server=None,
        )
        return obj, ctx

    def test_dry_run_renewal_master(self):
        """Dry-run renewal master returns 0.

        Pre-flight checks (pki-server, CA cert validity)
        run after dry-run, so dry-run always succeeds.
        """
        obj, ctx = self._make_certfix_with_dry_run()
        ctx.scenario = FixScenario.RENEWAL_MASTER
        result = obj.run_renewal_master_fix(ctx)
        assert result == 0

    def test_dry_run_ca_full_with_master(self):
        """Dry-run CA-full with master returns 0."""
        obj, ctx = self._make_certfix_with_dry_run()
        ctx.scenario = FixScenario.CA_FULL_WITH_MASTER
        ctx.master_server = 'master.example.com'
        result = obj._run_non_rm_replica_fix(ctx, is_ca_full=True)
        assert result == 0

    def test_dry_run_ca_less_with_master(self):
        """Dry-run CA-less with master returns 0."""
        obj, ctx = self._make_certfix_with_dry_run()
        ctx.scenario = FixScenario.CA_LESS_WITH_MASTER
        ctx.master_server = 'master.example.com'
        result = obj._run_non_rm_replica_fix(ctx, is_ca_full=False)
        assert result == 0


class TestUnitValidateOptions:
    """Unit tests for option validation."""

    @mock.patch('ipapython.admintool.AdminTool.validate_options')
    def test_renewal_master_and_force_server_exclusive(
        self, mock_super,
    ):
        """--renewal-master + --force-server is rejected."""
        from ipaserver.install.ipa_cert_fix import IPACertFix

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.renewal_master = True
        obj.options.force_server = 'master.example.com'
        obj.option_parser = mock.MagicMock()

        obj.validate_options()

        obj.option_parser.error.assert_called_once()
        assert "mutually exclusive" in \
            obj.option_parser.error.call_args[0][0]

    def test_renewal_master_on_caless_rejected(self):
        """--renewal-master on CA-less raises RuntimeError."""
        options = mock.MagicMock()
        options.renewal_master = True
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=options,
        )

        with pytest.raises(RuntimeError, match="CA-less"):
            obj.determine_scenario(DeploymentType.CA_LESS)

    def test_renewal_master_on_caless_external_rejected(self):
        """--renewal-master on CA_LESS_EXTERNAL raises RuntimeError."""
        options = mock.MagicMock()
        options.renewal_master = True
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=options,
        )

        with pytest.raises(RuntimeError, match="CA-less"):
            obj.determine_scenario(DeploymentType.CA_LESS_EXTERNAL)


class TestUnitPostRenewalCACheck:
    """Verify CA cert is checked after pki-server cert-fix."""

    @mock.patch(MODULE + '.api')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.run_cert_fix')
    @mock.patch(MODULE + '.fix_certreq_directives')
    def test_ca_still_expired_returns_1(
        self, mock_fix, mock_rcf,
        mock_ipautil, mock_api,
    ):
        """If CA cert is still expired after cert-fix, exit 1."""
        from ipaserver.install.ipa_cert_fix import (
            IPACertFix, CertFixContext,
        )

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = True
        # Pre-flight passes, post-renewal fails
        obj._detector = mock.MagicMock()
        obj._detector._check_ca_signing_cert = mock.MagicMock(
            side_effect=[True, False]
        )
        obj._detector.check_is_renewal_master = mock.MagicMock(
            return_value=True)

        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.RENEWAL_MASTER,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[('ca_issuing', cert)],
            ipa_certs=[],
            external_certs=[],
            master_server=None,
        )
        result = obj.run_renewal_master_fix(ctx)
        assert result == 1
        assert obj._detector._check_ca_signing_cert.call_count == 2


class TestUnitExternalCertsNoCA:
    """T-EXT-7: Fully external, no internal CA."""

    @mock.patch(SMOD + '.os.makedirs')
    @mock.patch(SMOD + '.find_providing_servers')
    def test_caless_external_skips_ca_lookup(
        self, mock_fps, mock_makedirs,
    ):
        """CA_LESS_EXTERNAL skips CA server lookup entirely.

        No transition is offered; manual instructions printed.
        """
        from ipaserver.install.ipa_cert_fix import CertFixContext

        cm = mock.MagicMock()
        cm.get_request_id.return_value = None
        handler = ExternalCertHandler(
            cm_client=cm, unattended=True,
        )
        # Mock CSR generation to avoid hitting DN/api
        handler._generate_csr_from_key = mock.MagicMock(
            return_value=None,
        )

        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_LESS_EXTERNAL,
            scenario=FixScenario.EXTERNAL_CERTS,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[], ipa_certs=[],
            external_certs=[
                (IPACertType.HTTPS, cert),
            ],
            master_server=None,
        )
        handler.handle(ctx)

        # find_providing_servers must NOT be called
        mock_fps.assert_not_called()

    def test_no_tracking_generates_csr_from_key(self, tmp_path):
        """When no tracking exists, generate CSR from key.

        Externally-signed certs typically have tracking stopped.
        The tool should generate CSRs from the existing private
        keys and print ipa-server-certinstall commands.
        """
        from ipaserver.install.ipa_cert_fix import CertFixContext

        cm = mock.MagicMock()
        cm.get_request_id.return_value = None
        handler = ExternalCertHandler(
            cm_client=cm, unattended=True,
            csr_dir=str(tmp_path),
        )
        # Mock CSR generation to return a fake CSR
        fake_csr = (
            "-----BEGIN CERTIFICATE REQUEST-----\nfake\n"
            "-----END CERTIFICATE REQUEST-----\n"
        )
        handler._generate_csr_from_key = mock.MagicMock(
            return_value=fake_csr
        )

        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_LESS_EXTERNAL,
            scenario=FixScenario.EXTERNAL_CERTS,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[], ipa_certs=[],
            external_certs=[
                (IPACertType.HTTPS, cert),
            ],
            master_server=None,
        )
        import io
        import sys
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            handler.handle(ctx)
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        assert 'ipa-server-certinstall --http' in output
        assert 'CSR:' in output
        handler._generate_csr_from_key.assert_called_once()


class TestUnitBuildTrackingList:
    """Unit tests for _build_tracking_list filtering logic."""

    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.api')
    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid',
                return_value='TEST')
    def test_skips_subsystem_and_ra(
        self, mock_r2s, mock_ds, mock_api, mock_nss,
    ):
        """subsystem and RA certs are skipped (fetched
        separately from master's LDAP).
        """
        from ipaserver.install.ipa_cert_fix import (
            CertRenewalFromMaster, CertFixContext,
        )

        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.CA_FULL_WITH_MASTER,
            subject_base='O=TEST',
            ca_subject_dn='CN=CA',
            dogtag_certs=[], ipa_certs=[],
            external_certs=[],
            master_server='m.example.com',
            serverid='TEST',
            ds_dbdir='/etc/dirsrv/slapd-TEST',
            ds_nickname='Server-Cert',
        )

        dogtag = [
            ('subsystem', cert), ('sslserver', cert),
        ]
        ipa = [
            (IPACertType.IPARA, cert), (IPACertType.HTTPS, cert),
        ]

        obj = CertRenewalFromMaster(mock.MagicMock(), 'm.example.com')
        tracking = obj._build_tracking_list(dogtag, ipa, ctx)

        descs = [d for d, _c, _cr, _l in tracking]
        desc_ids = [getattr(d, 'id', d) for d in descs]
        # subsystem and RA must be skipped
        assert 'subsystem' not in desc_ids
        assert IPACertType.IPARA not in descs
        # sslserver and HTTPS must be present
        assert 'sslserver' in desc_ids
        assert IPACertType.HTTPS in descs

    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.api')
    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid',
                return_value='TEST')
    def test_all_ipa_cert_types_mapped(
        self, mock_r2s, mock_ds, mock_api, mock_nss,
    ):
        """HTTPS, LDAPS, KDC all produce tracking entries."""
        from ipaserver.install.ipa_cert_fix import (
            CertRenewalFromMaster, CertFixContext,
        )

        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.CA_FULL_WITH_MASTER,
            subject_base='O=TEST',
            ca_subject_dn='CN=CA',
            dogtag_certs=[], ipa_certs=[],
            external_certs=[],
            master_server='m.example.com',
            serverid='TEST',
            ds_dbdir='/etc/dirsrv/slapd-TEST',
            ds_nickname='Server-Cert',
        )

        ipa = [
            (IPACertType.HTTPS, cert), (IPACertType.LDAPS, cert),
            (IPACertType.KDC, cert),
        ]

        obj = CertRenewalFromMaster(mock.MagicMock(), 'm.example.com')
        tracking = obj._build_tracking_list([], ipa, ctx)

        descs = [d for d, _c, _cr, _l in tracking]
        assert IPACertType.HTTPS in descs
        assert IPACertType.LDAPS in descs
        assert IPACertType.KDC in descs
        assert len(tracking) == 3


class TestUnitMakeCertLoader:
    """Unit tests for _make_cert_loader factory."""

    @mock.patch(SMOD + '.NSSDatabase')
    def test_nssdb_loader(self, mock_nss):
        """NSSDB loader calls db.get_cert(nickname)."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        db = mock.MagicMock()
        mock_nss.return_value = db

        loader = CertRenewalFromMaster._make_cert_loader(
            'NSSDB', '/some/db', 'MyCert'
        )
        loader()
        db.get_cert.assert_called_once_with('MyCert')

    @mock.patch(SMOD + '.x509')
    def test_file_loader(self, mock_x509):
        """FILE loader calls load_certificate_from_file."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        loader = CertRenewalFromMaster._make_cert_loader(
            'FILE', '/some/cert.pem'
        )
        loader()
        mock_x509.load_certificate_from_file \
            .assert_called_once_with('/some/cert.pem')


class TestUnitSetIpaCaHelperStripping:
    """Verify _set_helper strips leftover -J."""

    @mock.patch(SMOD + '.certmonger')
    def test_strips_stale_j_flag(self, mock_cm):
        """If old helper already has -J from a crashed run,
        the stale -J is stripped before appending the new one.

        Logic now lives in CertmongerClient.set_ca_override.
        """
        stale = ('/usr/libexec/ipa-submit -J https://old.example.com/ipa/json')
        client = CertmongerClient()
        client.get_ca_helper = mock.MagicMock(return_value=stale)

        result = client.set_ca_override('IPA', 'new.example.com')

        assert result == '/usr/libexec/ipa-submit'
        call_args = mock_cm.modify_ca_helper.call_args
        new_helper = call_args[0][1]
        assert new_helper.count('-J') == 1
        assert 'new.example.com' in new_helper


class TestUnitGenerateCsrFromKey:
    """Verify _generate_csr_from_key logic."""

    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '.ipa_certs')
    def test_returns_none_on_missing_key(
        self, mock_certs, mock_api,
    ):
        """If key file doesn't exist, returns None."""
        from ipaserver.install.ipa_cert_fix import CertFixContext

        mock_api.env.host = 'h.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'
        mock_api.env.domain = 'example.com'
        mock_certs.get_default_profile.return_value = ('caIPAserviceCert')

        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.RENEWAL_MASTER,
            subject_base='O=EXAMPLE.COM',
            ca_subject_dn='CN=CA',
            dogtag_certs=[], ipa_certs=[],
            external_certs=[], master_server=None,
            serverid='X',
            ds_dbdir='/etc/dirsrv/slapd-X',
            ds_nickname='Server-Cert',
        )

        handler = ExternalCertHandler(cm_client=mock.MagicMock())
        cert = mock.MagicMock()
        # Use a nonexistent key file
        result = handler._generate_csr_from_key(
            IPACertType.HTTPS, cert, ctx
        )
        # Should return None (key file missing)
        assert result is None


class TestUnitUpdateCaCertChainCheck:
    """Verify update_ca_cert_from_master chain validation."""

    @mock.patch(MODULE + '.x509')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid',
                return_value='X')
    def test_missing_chain_raises(
        self, mock_r2s, mock_ds, mock_ipautil,
        mock_x509,
    ):
        """If CA chain file is unreadable after
        ipa-certupdate, RuntimeError is raised.
        """
        from ipaserver.install.ipa_cert_fix import (
            IPACertFix,
        )

        mock_run = mock.MagicMock()
        mock_run.returncode = 1
        mock_ipautil.run.return_value = mock_run
        mock_x509.load_certificate_list_from_file \
            .side_effect = IOError("not found")

        obj = object.__new__(IPACertFix)
        with mock.patch(MODULE + '.paths') as mp:
            mp.IPA_CA_CRT = '/nonexistent'
            try:
                obj.update_ca_cert_from_master('m')
                assert False, 'Should have raised'
            except RuntimeError as e:
                assert 'not available' in str(e)


class TestUnitVerifyCaChainValid:
    """Unit tests for _verify_ca_chain_valid chain walking."""

    def _make_cert(self, subject_dn, issuer_dn, expired=False):
        """Create a mock cert with string DN subject/issuer."""
        import datetime as dt
        from cryptography.x509 import Name, NameAttribute
        from cryptography.x509.oid import NameOID
        cert = mock.MagicMock()
        # Use real x509.Name objects so DN() works
        cert.subject = Name([NameAttribute(NameOID.COMMON_NAME, subject_dn)])
        cert.issuer = Name([NameAttribute(NameOID.COMMON_NAME, issuer_dn)])
        if expired:
            cert.not_valid_after_utc = dt.datetime(
                2020, 1, 1, tzinfo=dt.timezone.utc)
        else:
            cert.not_valid_after_utc = dt.datetime(
                2030, 1, 1, tzinfo=dt.timezone.utc)
        return cert

    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_valid_self_signed_chain(self, mock_paths, mock_x509, mock_nss):
        """Self-signed CA: single cert, subject==issuer, valid."""
        cert = self._make_cert('IPA CA', 'IPA CA')
        mock_x509.load_certificate_list_from_file.return_value = [cert]
        db = mock.MagicMock()
        db.get_cert.return_value = cert
        mock_nss.return_value = db
        DeploymentDetector._verify_ca_chain_valid('master.example.com')

    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_expired_issuing_cert_raises(
        self, mock_paths, mock_x509, mock_nss,
    ):
        """Expired issuing CA cert raises RuntimeError."""
        cert = self._make_cert('IPA CA', 'IPA CA', expired=True)
        mock_x509.load_certificate_list_from_file.return_value = [cert]
        db = mock.MagicMock()
        db.get_cert.return_value = cert
        mock_nss.return_value = db
        with pytest.raises(RuntimeError, match="expired"):
            DeploymentDetector._verify_ca_chain_valid('master.example.com')

    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_expired_intermediate_raises(
        self, mock_paths, mock_x509, mock_nss,
    ):
        """Expired intermediate in chain raises RuntimeError."""
        root = self._make_cert('Root CA', 'Root CA')
        inter = self._make_cert('IPA CA', 'Root CA', expired=True)
        leaf = self._make_cert('Sub CA', 'IPA CA')
        mock_x509.load_certificate_list_from_file.return_value = [
            leaf, inter, root]
        db = mock.MagicMock()
        db.get_cert.return_value = leaf
        mock_nss.return_value = db
        with pytest.raises(RuntimeError, match="expired"):
            DeploymentDetector._verify_ca_chain_valid('master.example.com')

    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_incomplete_chain_raises(self, mock_paths, mock_x509, mock_nss):
        """Missing issuer in chain raises RuntimeError."""
        leaf = self._make_cert('IPA CA', 'Root CA')
        mock_x509.load_certificate_list_from_file.return_value = [leaf]
        db = mock.MagicMock()
        db.get_cert.return_value = leaf
        mock_nss.return_value = db
        with pytest.raises(RuntimeError, match="Incomplete"):
            DeploymentDetector._verify_ca_chain_valid('master.example.com')

    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_caless_uses_first_cert(self, mock_paths, mock_x509, mock_nss):
        """CA-less: NSS fails, uses first cert in file."""
        cert = self._make_cert('IPA CA', 'IPA CA')
        mock_x509.load_certificate_list_from_file.return_value = [cert]
        mock_nss.side_effect = Exception("no NSSDB")
        DeploymentDetector._verify_ca_chain_valid('master.example.com')

    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_duplicate_subject_prefers_valid(
        self, mock_paths, mock_x509, mock_nss,
    ):
        """Duplicate-subject certs: prefer valid over expired.

        After CA renewal, ca.crt contains both old (expired) and new
        (valid) CA certs with the same subject DN.  The chain walker
        must pick the valid one regardless of file ordering.
        """
        old_ca = self._make_cert('IPA CA', 'IPA CA', expired=True)
        new_ca = self._make_cert('IPA CA', 'IPA CA')
        # expired cert comes LAST -- would overwrite in naive dict
        mock_x509.load_certificate_list_from_file.return_value = [
            new_ca, old_ca]
        db = mock.MagicMock()
        db.get_cert.return_value = new_ca
        mock_nss.return_value = db
        # Should not raise -- valid cert should be preferred
        DeploymentDetector._verify_ca_chain_valid('master.example.com')


class TestUnitResubmitSkipStates:
    """Unit tests for resubmit_expired_certs skip/error logic."""

    def test_monitoring_skipped(self):
        """Certs in MONITORING are skipped."""
        from ipaserver.install.ipa_cert_fix import IPACertFix

        obj = object.__new__(IPACertFix)
        obj._cm = mock.MagicMock()
        obj._cm.get_requests_for_dir.return_value = ['req1']
        obj._cm.get_request_id.return_value = None
        obj._cm.get_request_value.return_value = 'MONITORING'
        obj.options = mock.MagicMock()
        obj._is_cert_valid = mock.MagicMock(return_value=True)

        with mock.patch(MODULE + '.dsinstance') as md, \
             mock.patch(MODULE + '.realm_to_serverid',
                        return_value='TESTID'), \
             mock.patch(MODULE + '.api') as mapi:
            mapi.env.realm = 'TEST.REALM'
            md.config_dirname.return_value = '/etc/dirsrv/slapd-TESTID/'
            obj.resubmit_expired_certs(renewed_ids=set())

        # Should NOT resubmit -- cert is valid
        obj._cm.resubmit_request.assert_not_called()

    def test_renewed_ids_skipped(self):
        """Certs already renewed from master are skipped."""
        from ipaserver.install.ipa_cert_fix import IPACertFix

        obj = object.__new__(IPACertFix)
        obj._cm = mock.MagicMock()
        obj._cm.get_requests_for_dir.return_value = ['req1']
        obj._cm.get_request_id.return_value = None
        obj.options = mock.MagicMock()

        with mock.patch(MODULE + '.dsinstance') as md, \
             mock.patch(MODULE + '.realm_to_serverid',
                        return_value='TESTID'), \
             mock.patch(MODULE + '.api') as mapi:
            mapi.env.realm = 'TEST.REALM'
            md.config_dirname.return_value = '/etc/dirsrv/slapd-TESTID/'
            obj.resubmit_expired_certs(renewed_ids={'req1'})

        # Should NOT resubmit -- already renewed
        obj._cm.resubmit_request.assert_not_called()


class TestUnitCheckRenewedIpaCerts:
    """Unit tests for check_renewed_ipa_certs validation."""

    def _make_cert(self, serial, expired=False):
        import datetime as dt
        cert = mock.MagicMock()
        cert.serial_number = serial
        if expired:
            cert.not_valid_after_utc = dt.datetime(
                2020, 1, 1, tzinfo=dt.timezone.utc)
        else:
            cert.not_valid_after_utc = dt.datetime(
                2030, 1, 1, tzinfo=dt.timezone.utc)
        return cert

    @mock.patch(MODULE + '.x509')
    def test_same_serial_rejected(self, mock_x509):
        """Renewed cert with same serial as old is rejected."""
        from ipaserver.install.ipa_cert_fix import (
            check_renewed_ipa_certs,
        )

        old = self._make_cert(42)
        new = self._make_cert(42)  # same serial
        mock_x509.load_certificate_from_file.return_value = new

        result = check_renewed_ipa_certs([(IPACertType.HTTPS, old)])
        assert result is False

    @mock.patch(MODULE + '.x509')
    def test_expired_renewed_cert_rejected(self, mock_x509):
        """Renewed cert that is expired is rejected."""
        from ipaserver.install.ipa_cert_fix import (
            check_renewed_ipa_certs,
        )

        old = self._make_cert(42)
        new = self._make_cert(99, expired=True)
        mock_x509.load_certificate_from_file.return_value = new

        result = check_renewed_ipa_certs([(IPACertType.HTTPS, old)])
        assert result is False

    @mock.patch(MODULE + '.x509')
    def test_valid_renewal_accepted(self, mock_x509):
        """Renewed cert with new serial and valid expiry passes."""
        from ipaserver.install.ipa_cert_fix import (
            check_renewed_ipa_certs,
        )

        old = self._make_cert(42)
        new = self._make_cert(99)  # different serial, valid
        mock_x509.load_certificate_from_file.return_value = new

        result = check_renewed_ipa_certs([(IPACertType.HTTPS, old)])
        assert result is True


class TestUnitDetectMismatches:
    """Unit tests for _detect_ra_subsystem_mismatches."""

    def _make_cert(self, serial, subject='CN=Test'):
        import datetime as dt
        from cryptography.x509 import Name, NameAttribute
        from cryptography.x509.oid import NameOID
        cert = mock.MagicMock()
        cert.serial_number = serial
        cert.subject = Name([NameAttribute(NameOID.COMMON_NAME, subject)])
        cert.issuer = Name([NameAttribute(NameOID.COMMON_NAME, 'CN=CA')])
        cert.not_valid_after_utc = dt.datetime(
            2030, 1, 1, tzinfo=dt.timezone.utc)
        cert.public_bytes.return_value = (b'cert-%d' % serial)
        return cert

    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '._get_pki_nssdb')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_ldap_newer_detected(
        self, _paths, mock_x509, mock_nssdb, mock_api,
    ):
        """Detects when LDAP has a newer cert than local."""
        local_cert = self._make_cert(10)
        ldap_cert = self._make_cert(20)

        mock_x509.load_certificate_from_file.return_value = local_cert
        mock_x509.Encoding.DER = 'DER'

        entry = mock.MagicMock()
        entry.get.return_value = [ldap_cert]
        entry.single_value.get.return_value = ''
        mock_api.Backend.ldap2.get_entry.return_value = entry

        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )
        mismatches = obj._detect_ra_subsystem_mismatches(skip_subsystem=True)

        assert len(mismatches) == 1
        assert mismatches[0]['update_local'] is True

    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '._get_pki_nssdb')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_consistent_no_mismatch(
        self, _paths, mock_x509, mock_nssdb, mock_api,
    ):
        """No mismatch when local and LDAP match."""
        from ipapython.dn import DN

        cert = self._make_cert(10)

        mock_x509.load_certificate_from_file.return_value = cert
        mock_x509.Encoding.DER = 'DER'

        expected_desc = '2;%d;%s;%s' % (
            cert.serial_number,
            DN(cert.issuer), DN(cert.subject))
        entry = mock.MagicMock()
        entry.get.return_value = [cert]
        entry.single_value.get.return_value = expected_desc
        mock_api.Backend.ldap2.get_entry.return_value = entry

        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )
        mismatches = obj._detect_ra_subsystem_mismatches(skip_subsystem=True)

        assert len(mismatches) == 0


class TestUnitPartialRenewalFailure:
    """Partial failure in CertRenewalFromMaster.renew."""

    def test_failed_cert_not_in_renewed_ids(self):
        """Failed certs excluded from renewed_ids."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        obj = CertRenewalFromMaster(mock.MagicMock(), 'master.example.com')

        # Mock two tracking requests
        obj._build_tracking_list = mock.MagicMock(return_value=[
            ('sslserver', mock.MagicMock(), {}, mock.MagicMock()),
            ('httpd', mock.MagicMock(), {}, mock.MagicMock()),
        ])
        obj._resolve_tracking_requests = mock.MagicMock(
            return_value=[
                ('sslserver', mock.MagicMock(), 'req1', 'dogtag', None),
                ('httpd', mock.MagicMock(), 'req2', 'IPA', None),
            ])
        obj._set_helper = mock.MagicMock(return_value='old')
        obj._restore_helper = mock.MagicMock()
        obj._restore = mock.MagicMock()

        # First cert succeeds, second fails
        obj._resubmit = mock.MagicMock(
            side_effect=[None, RuntimeError("timeout")])

        ctx = mock.MagicMock()
        ctx.dogtag_certs = []
        ctx.ipa_certs = []
        result = obj.renew([], [], ctx)

        # Only the successful cert should be in renewed_ids
        assert 'req1' in result
        assert 'req2' not in result


class TestUnitResubmitUnexpectedState:
    """resubmit_expired_certs with unexpected certmonger state."""

    def test_unknown_state_logged(self):
        """Certs in unknown states are not resubmitted."""
        from ipaserver.install.ipa_cert_fix import IPACertFix

        obj = object.__new__(IPACertFix)
        obj._cm = mock.MagicMock()
        obj._cm.get_requests_for_dir.return_value = ['req1']
        obj._cm.get_request_id.return_value = None
        obj._cm.get_request_value.return_value = 'WEIRD_STATE'
        obj.options = mock.MagicMock()
        obj._is_cert_valid = mock.MagicMock(return_value=False)

        with mock.patch(MODULE + '.dsinstance') as md, \
             mock.patch(MODULE + '.realm_to_serverid',
                        return_value='TESTID'), \
             mock.patch(MODULE + '.api') as mapi:
            mapi.env.realm = 'TEST.REALM'
            md.config_dirname.return_value = '/etc/dirsrv/slapd-TESTID/'
            obj.resubmit_expired_certs(renewed_ids=set())

        # Unknown state -- should not resubmit
        obj._cm.resubmit_request.assert_not_called()


class TestUnitSetHelperTimeout:
    """D-Bus timeout in _set_helper."""

    def test_dbus_timeout_raises(self):
        """_set_helper raises when set_ca_override fails."""
        import dbus
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        cm = mock.MagicMock()
        cm.set_ca_override.side_effect = \
            dbus.exceptions.DBusException("timeout")

        obj = CertRenewalFromMaster(cm, 'master.example.com')
        with pytest.raises(dbus.exceptions.DBusException):
            obj._set_helper()


class TestUnitPromoteRollback:
    """run_ca_full_promote rollback on failure."""

    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '._find_current_renewal_master',
                return_value='old-master.example.com')
    @mock.patch(MODULE + '.api')
    def test_rm_restored_on_failure(self, mock_api, mock_find_rm,
                                    mock_ipautil):
        """Renewal master is rolled back if cert fix fails."""
        from ipaserver.install.ipa_cert_fix import (
            IPACertFix, CertFixContext,
        )

        mock_ipautil.run.return_value = mock.MagicMock(returncode=0)
        mock_ipautil.CalledProcessError = Exception
        mock_api.env.host = 'replica.example.com'

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = False
        obj._scenario_made_changes = False

        # Mock the promote/fix chain
        obj._promote_to_renewal_master = mock.MagicMock()
        obj._ca_instance = mock.MagicMock()
        obj.run_renewal_master_fix = mock.MagicMock(
            side_effect=RuntimeError("cert-fix failed"))

        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.CA_FULL_PROMOTE,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[], ipa_certs=[],
            external_certs=[],
            master_server=None,
            serverid='TESTID',
            ds_dbdir='/etc/dirsrv/slapd-TESTID',
            ds_nickname='Server-Cert',
            hsm_enabled=False,
            hsm_token_name=None,
        )

        # Simulate user confirming promotion
        with mock.patch(MODULE + '.ipautil.user_input', return_value='yes'):
            with pytest.raises(RuntimeError, match="cert-fix failed"):
                obj.run_ca_full_promote(ctx)

        # Rollback should have been attempted
        obj._ca_instance.set_renewal_master.assert_called_with(
            'old-master.example.com')


class TestUnitFetchSharedPartialFailure:
    """_fetch_shared_dogtag_certs with some certs failing."""

    @mock.patch(SMOD + '.api')
    def test_one_fails_others_succeed(self, mock_api):
        """Failed shared cert doesn't block other certs."""
        import datetime as dt
        from ipaserver.install.ipa_cert_fix import IPACertFix

        mock_api.env.basedn = 'dc=example,dc=com'

        now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        good_cert = mock.MagicMock()
        good_cert.not_valid_after_utc = dt.datetime(
            2030, 1, 1, tzinfo=dt.timezone.utc)
        good_cert.serial_number = 99

        conn = mock.MagicMock()
        db = mock.MagicMock()

        # First cert fetch fails, second succeeds
        entry_ok = mock.MagicMock()
        entry_ok.single_value.__getitem__ = mock.MagicMock(
            return_value=good_cert)

        call_count = [0]

        def get_entry_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("LDAP error")
            return entry_ok

        conn.get_entry.side_effect = get_entry_side_effect

        ctx = mock.MagicMock()
        ctx.dogtag_certs = [
            ('ca_ocsp_signing', mock.MagicMock()),
            ('ca_audit_signing', mock.MagicMock()),
        ]

        obj = object.__new__(IPACertFix)
        # Should not raise -- failed cert logged, loop continues
        obj._fetch_shared_dogtag_certs(
            conn, db, ctx, 'master.example.com', now)

        # Second cert should have been installed despite first failing
        assert db.add_cert.called or conn.get_entry.call_count == 2


# =============================================================
#  Phase 1: CertIdentity Tests
# =============================================================


class TestCertIdentityRegistry:
    """Phase 1.1: CertIdentity dataclass and DOGTAG_CERTS registry."""

    def test_sslserver_is_not_shared(self):
        """sslserver is server-specific, not shared/replicated."""
        assert DOGTAG_CERTS['sslserver'].is_shared is False

    def test_subsystem_is_shared(self):
        assert DOGTAG_CERTS['subsystem'].is_shared is True

    def test_ca_issuing_is_shared(self):
        assert DOGTAG_CERTS['ca_issuing'].is_shared is True

    def test_all_entries_are_cert_identity(self):
        for certid, ci in DOGTAG_CERTS.items():
            assert isinstance(ci, CertIdentity), certid

    def test_all_ids_match_keys(self):
        for certid, ci in DOGTAG_CERTS.items():
            assert ci.id == certid

    def test_all_have_nickname(self):
        for certid, ci in DOGTAG_CERTS.items():
            assert ci.nickname, certid

    def test_all_shared_certs_have_cs_cfg_directive(self):
        """Shared certs (except ca_issuing and sslserver) must have
        CS.cfg directives so _update_cs_cfg can update them."""
        for certid, ci in DOGTAG_CERTS.items():
            if ci.is_shared and certid not in ('ca_issuing',):
                assert ci.cs_cfg_directive is not None, (
                    "%s is shared but has no cs_cfg_directive" % certid)
                assert ci.cfg_path is not None, (
                    "%s is shared but has no cfg_path" % certid)

    def test_sslserver_has_no_cs_cfg_directive(self):
        """sslserver CS.cfg is updated by certmonger post-save."""
        assert DOGTAG_CERTS['sslserver'].cs_cfg_directive is None

    def test_ca_issuing_has_no_cs_cfg_directive(self):
        """ca_issuing is handled by ipa-certupdate."""
        assert DOGTAG_CERTS['ca_issuing'].cs_cfg_directive is None

    def test_registry_has_all_eight_certs(self):
        expected = {
            'ca_issuing', 'sslserver', 'subsystem',
            'ca_ocsp_signing', 'ca_audit_signing',
            'kra_transport', 'kra_storage', 'kra_audit_signing',
        }
        assert set(DOGTAG_CERTS.keys()) == expected

    def test_certreq_directives_present(self):
        """All non-ca_issuing certs have certreq directives for
        fix_certreq_directives."""
        for certid, ci in DOGTAG_CERTS.items():
            if certid != 'ca_issuing':
                assert ci.certreq_directive is not None, (
                    "%s has no certreq_directive" % certid)

    def test_frozen(self):
        """CertIdentity is immutable."""
        ci = DOGTAG_CERTS['sslserver']
        with pytest.raises(AttributeError):
            ci.id = 'changed'

    def test_display_name(self):
        """display_name returns the NSSDB nickname."""
        ci = DOGTAG_CERTS['sslserver']
        assert ci.display_name == 'Server-Cert cert-pki-ca'

    def test_is_dogtag(self):
        """All CertIdentity instances report is_dogtag=True."""
        for ci in DOGTAG_CERTS.values():
            assert ci.is_dogtag is True


class TestCertmongerClient:
    """Phase 2: CertmongerClient adapter tests."""

    @mock.patch(SMOD + '.certmonger')
    def test_get_request_id_delegates(self, mock_cm):
        mock_cm.get_request_id.return_value = 'req-1'
        client = CertmongerClient()
        result = client.get_request_id({'cert-file': '/a'})
        assert result == 'req-1'
        mock_cm.get_request_id.assert_called_once_with({'cert-file': '/a'})

    @mock.patch(SMOD + '.certmonger')
    def test_get_request_value_delegates(self, mock_cm):
        mock_cm.get_request_value.return_value = 'MONITORING'
        client = CertmongerClient()
        result = client.get_request_value('req-1', 'status')
        assert result == 'MONITORING'

    @mock.patch(SMOD + '.certmonger')
    def test_resubmit_request_delegates(self, mock_cm):
        client = CertmongerClient()
        client.resubmit_request('req-1', ca='IPA')
        mock_cm.resubmit_request.assert_called_once_with(
            'req-1', ca='IPA', profile=None)

    @mock.patch(SMOD + '.certmonger')
    def test_modify_ca_helper_delegates(self, mock_cm):
        client = CertmongerClient()
        client.modify_ca_helper('IPA', '/usr/libexec/ipa-submit')
        mock_cm.modify_ca_helper.assert_called_once_with(
            'IPA', '/usr/libexec/ipa-submit')

    @mock.patch(SMOD + '.time.sleep')
    @mock.patch(SMOD + '.time.monotonic')
    @mock.patch(SMOD + '.ipautil')
    def test_is_responsive_returns_true(
        self, mock_ipautil, mock_mono, mock_sleep,
    ):
        mock_ipautil.run.return_value = mock.MagicMock()
        mock_mono.return_value = 0
        client = CertmongerClient()
        assert client.is_responsive(timeout=10) is True

    @mock.patch(SMOD + '.time.sleep')
    @mock.patch(SMOD + '.time.monotonic')
    @mock.patch(SMOD + '.ipautil')
    def test_is_responsive_timeout_returns_false(
        self, mock_ipautil, mock_mono, mock_sleep,
    ):
        mock_ipautil.run.side_effect = Exception("D-Bus down")
        mock_mono.side_effect = [0, 0, 200]
        client = CertmongerClient()
        assert client.is_responsive(timeout=1) is False

    @mock.patch(SMOD + '.certmonger')
    def test_start_tracking_delegates(self, mock_cm):
        mock_cm.start_tracking.return_value = 'new-req'
        client = CertmongerClient()
        result = client.start_tracking(certpath='/cert', ca='IPA')
        assert result == 'new-req'

    @mock.patch(SMOD + '.certmonger')
    def test_stop_tracking_delegates(self, mock_cm):
        client = CertmongerClient()
        client.stop_tracking('req-1')
        mock_cm.stop_tracking.assert_called_once_with(request_id='req-1')

    @mock.patch(SMOD + '.certmonger')
    def test_get_requests_for_dir_delegates(self, mock_cm):
        mock_cm.get_requests_for_dir.return_value = ['r1', 'r2']
        client = CertmongerClient()
        result = client.get_requests_for_dir('/etc/pki')
        assert result == ['r1', 'r2']


# =============================================================
#  Phase 0: Characterization Tests (Safety Net)
#
#  Pin current behavior before refactoring.  Each test documents
#  what the code does today, not what it should do.
# =============================================================


class TestUnitDeploymentDetection:
    """Characterization: detect_deployment_type with all 4 return values."""

    def _make_detector(self):
        return DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=None,
            options=mock.MagicMock(),
        )

    @mock.patch(SMOD + '.find_providing_servers')
    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '._get_pki_nssdb')
    @mock.patch(SMOD + '.cainstance')
    def test_ca_self_signed(
        self, mock_ca, mock_nssdb, mock_api, mock_fps,
    ):
        """CA installed, issuer == subject -> CA_SELF_SIGNED."""
        mock_ca.is_ca_installed_locally.return_value = True
        cert = mock.MagicMock()
        cert.issuer = 'CN=Certificate Authority,O=EXAMPLE.COM'
        cert.subject = 'CN=Certificate Authority,O=EXAMPLE.COM'
        mock_nssdb.return_value.get_cert.return_value = cert

        obj = self._make_detector()
        result = obj.detect_deployment_type()
        assert result == DeploymentType.CA_SELF_SIGNED

    @mock.patch(SMOD + '.find_providing_servers')
    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '._get_pki_nssdb')
    @mock.patch(SMOD + '.cainstance')
    def test_ca_externally_signed(
        self, mock_ca, mock_nssdb, mock_api, mock_fps,
    ):
        """CA installed, issuer != subject -> CA_EXTERNALLY_SIGNED."""
        mock_ca.is_ca_installed_locally.return_value = True
        cert = mock.MagicMock()
        cert.issuer = 'CN=External Root CA,O=EXTCA'
        cert.subject = 'CN=Certificate Authority,O=EXAMPLE.COM'
        mock_nssdb.return_value.get_cert.return_value = cert

        obj = self._make_detector()
        result = obj.detect_deployment_type()
        assert result == DeploymentType.CA_EXTERNALLY_SIGNED

    @mock.patch(SMOD + '._ensure_ldap_connected')
    @mock.patch(SMOD + '.find_providing_servers',
                return_value=['ca1.example.com'])
    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '.cainstance')
    def test_ca_less_with_ca_servers(
        self, mock_ca, mock_api, mock_fps, mock_elc,
    ):
        """No local CA, CA servers in topology -> CA_LESS."""
        mock_ca.is_ca_installed_locally.return_value = False

        obj = self._make_detector()
        result = obj.detect_deployment_type()
        assert result == DeploymentType.CA_LESS

    @mock.patch(SMOD + '._ensure_ldap_connected')
    @mock.patch(SMOD + '.find_providing_servers', return_value=[])
    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '.cainstance')
    def test_ca_less_external(
        self, mock_ca, mock_api, mock_fps, mock_elc,
    ):
        """No local CA, no CA servers -> CA_LESS_EXTERNAL."""
        mock_ca.is_ca_installed_locally.return_value = False

        obj = self._make_detector()
        result = obj.detect_deployment_type()
        assert result == DeploymentType.CA_LESS_EXTERNAL

    @mock.patch(SMOD + '._ensure_ldap_connected')
    @mock.patch(SMOD + '.find_providing_servers',
                side_effect=Exception("LDAP down"))
    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '.cainstance')
    def test_ca_less_ldap_fails_defaults_to_ca_less(
        self, mock_ca, mock_api, mock_fps, mock_elc,
    ):
        """LDAP query failure on CA-less -> CA_LESS (not EXTERNAL)."""
        mock_ca.is_ca_installed_locally.return_value = False

        obj = self._make_detector()
        result = obj.detect_deployment_type()
        assert result == DeploymentType.CA_LESS

    @mock.patch(SMOD + '._ensure_ldap_connected')
    @mock.patch(SMOD + '.find_providing_servers',
                side_effect=Exception("LDAP down"))
    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '.cainstance')
    def test_detect2_ldap_query_fails_warns(
        self, mock_ca, mock_api, mock_fps, mock_elc, capsys,
    ):
        """T-DETECT-2: LDAP topology query fails during detection.

        Verify: warning printed, detection defaults to CA_LESS.
        """
        mock_ca.is_ca_installed_locally.return_value = False

        obj = self._make_detector()
        result = obj.detect_deployment_type()
        assert result == DeploymentType.CA_LESS
        captured = capsys.readouterr()
        assert 'WARNING' in captured.out
        assert 'Could not query topology' in captured.out

    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '._get_pki_nssdb')
    @mock.patch(SMOD + '.cainstance')
    def test_nssdb_unreadable_raises(
        self, mock_ca, mock_nssdb, mock_api,
    ):
        """CA installed but NSSDB unreadable -> RuntimeError."""
        mock_ca.is_ca_installed_locally.return_value = True
        mock_nssdb.return_value.get_cert.side_effect = RuntimeError("db error")

        obj = self._make_detector()
        with pytest.raises(RuntimeError, match="Cannot read caSigningCert"):
            obj.detect_deployment_type()


class TestUnitDetectAndDispatchNothingToDo:
    """Characterization: _classify_and_dispatch 'Nothing to do' path."""

    @mock.patch(MODULE + '.cainstance')
    @mock.patch(MODULE + '.ca')
    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid', return_value='EXAMPLE-COM')
    @mock.patch(MODULE + '.api')
    def test_no_expired_certs_no_mismatches_returns_zero(
        self, mock_api, mock_r2s, mock_ds, mock_ca_mod, mock_cai,
    ):
        """No expired certs + no LDAP mismatches -> exit 0."""
        from ipaserver.install.ipa_cert_fix import IPACertFix

        mock_cai.is_ca_installed_locally.return_value = False
        mock_api.env.realm = 'EXAMPLE.COM'
        ds_inst = mock.MagicMock()
        ds_inst.find_subject_base.return_value = 'O=EXAMPLE.COM'
        ds_inst.get_server_cert_nickname.return_value = 'Server-Cert'
        mock_ds.DsInstance.return_value = ds_inst
        mock_ds.config_dirname.return_value = '/etc/dirsrv/slapd-EXAMPLE-COM/'

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = True
        obj._ca_instance = None
        obj._scenario_made_changes = False
        obj._cm = mock.MagicMock()

        with mock.patch.object(
            DeploymentDetector, 'detect_deployment_type',
            return_value=DeploymentType.CA_LESS_EXTERNAL,
        ), mock.patch.object(
            DeploymentDetector, '_classify_certs',
            return_value=([], [], []),
        ):
            result = obj._classify_and_dispatch()
        assert result == 0


class TestUnitDetectAndDispatchLdapMismatchOnly:
    """Characterization: _classify_and_dispatch with only LDAP mismatches."""

    def _setup(self):
        from ipaserver.install.ipa_cert_fix import IPACertFix

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = False
        obj._ca_instance = mock.MagicMock()
        obj._scenario_made_changes = False
        obj._cm = mock.MagicMock()

        mismatch = {
            'label': 'IPA RA', 'newest': mock.MagicMock(serial_number=42),
            'dn': mock.MagicMock(),
            'entry': mock.MagicMock(),
            'update_local': False,
            'update_ldap_cert': False,
            'update_desc': True,
            'path_info': ('file', '/etc/pki/ra-agent.pem'),
            'expected_desc': '2;42;CN=CA;CN=RA',
        }
        obj._mock_mismatch = mismatch
        return obj

    @mock.patch(MODULE + '.print_intentions')
    @mock.patch(MODULE + '.ca')
    @mock.patch(MODULE + '.cainstance')
    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid', return_value='EXAMPLE-COM')
    @mock.patch(MODULE + '.api')
    def test_dry_run_shows_mismatches_no_fix(
        self, mock_api, mock_r2s, mock_ds, mock_cai,
        mock_ca_mod, mock_pi,
    ):
        """Dry-run with LDAP mismatches only -> shows plan, no fix."""
        mock_api.env.realm = 'EXAMPLE.COM'
        mock_cai.is_ca_installed_locally.return_value = True
        mock_cai.CAInstance.return_value = mock.MagicMock()
        ds_inst = mock.MagicMock()
        ds_inst.find_subject_base.return_value = 'O=EXAMPLE.COM'
        ds_inst.get_server_cert_nickname.return_value = 'Server-Cert'
        mock_ds.DsInstance.return_value = ds_inst
        mock_ds.config_dirname.return_value = '/etc/dirsrv/slapd-EXAMPLE-COM/'

        obj = self._setup()
        obj.options.dry_run = True

        with mock.patch.object(
            DeploymentDetector, 'detect_deployment_type',
            return_value=DeploymentType.CA_SELF_SIGNED,
        ), mock.patch.object(
            DeploymentDetector, '_classify_certs',
            return_value=([], [], []),
        ), mock.patch.object(
            DeploymentDetector, '_detect_ra_subsystem_mismatches',
            return_value=[obj._mock_mismatch],
        ), mock.patch.object(
            DeploymentDetector, '_fix_ra_subsystem_mismatches',
        ) as mock_fix:
            result = obj._classify_and_dispatch()
        assert result == 0
        mock_fix.assert_not_called()

    @mock.patch(MODULE + '.print_intentions')
    @mock.patch(MODULE + '.ca')
    @mock.patch(MODULE + '.cainstance')
    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid', return_value='EXAMPLE-COM')
    @mock.patch(MODULE + '.api')
    def test_unattended_fixes_mismatches(
        self, mock_api, mock_r2s, mock_ds, mock_cai,
        mock_ca_mod, mock_pi,
    ):
        """Unattended with LDAP mismatches only -> fixes applied, exit 0."""
        mock_api.env.realm = 'EXAMPLE.COM'
        mock_cai.is_ca_installed_locally.return_value = True
        mock_cai.CAInstance.return_value = mock.MagicMock()
        ds_inst = mock.MagicMock()
        ds_inst.find_subject_base.return_value = 'O=EXAMPLE.COM'
        ds_inst.get_server_cert_nickname.return_value = 'Server-Cert'
        mock_ds.DsInstance.return_value = ds_inst
        mock_ds.config_dirname.return_value = '/etc/dirsrv/slapd-EXAMPLE-COM/'

        obj = self._setup()
        obj.options.unattended = True

        with mock.patch.object(
            DeploymentDetector, 'detect_deployment_type',
            return_value=DeploymentType.CA_SELF_SIGNED,
        ), mock.patch.object(
            DeploymentDetector, '_classify_certs',
            return_value=([], [], []),
        ), mock.patch.object(
            DeploymentDetector, '_detect_ra_subsystem_mismatches',
            return_value=[obj._mock_mismatch],
        ), mock.patch.object(
            DeploymentDetector, '_fix_ra_subsystem_mismatches',
        ) as mock_fix:
            result = obj._classify_and_dispatch()
        assert result == 0
        mock_fix.assert_called_once()


class TestUnitRenewalMasterCalledProcessError:
    """Characterization: run_renewal_master_fix CalledProcessError tolerance."""

    def _make_obj(self):
        from ipaserver.install.ipa_cert_fix import IPACertFix
        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = True
        obj._scenario_made_changes = False
        obj._detector = mock.MagicMock()
        obj._detector._check_ca_signing_cert = mock.MagicMock(
            return_value=True)
        obj._detector.check_is_renewal_master = mock.MagicMock(
            return_value=True)
        obj._ca_instance = mock.MagicMock()
        obj._handle_external_certs = mock.MagicMock()
        obj._cm = mock.MagicMock()
        obj._cm.is_responsive.return_value = True
        obj.resubmit_expired_certs = mock.MagicMock()
        return obj

    @mock.patch(MODULE + '._ensure_ldap_connected')
    @mock.patch(MODULE + '.install_ipa_certs')
    @mock.patch(MODULE + '.replicate_dogtag_certs')
    @mock.patch(MODULE + '.check_renewed_ipa_certs', return_value=True)
    @mock.patch(MODULE + '.run_cert_fix',
                side_effect=Exception("pki-server failed"))
    @mock.patch(MODULE + '.fix_certreq_directives')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.api')
    def test_ds_cert_expired_tolerates_pki_error(
        self, mock_api, mock_ipautil, mock_fix_dir,
        mock_run_cf, mock_check, mock_repl, mock_install,
        mock_elc,
    ):
        """When DS cert is in the list and renewed files exist,
        CalledProcessError from pki-server cert-fix is tolerated."""
        from ipaserver.install.ipa_cert_fix import (
            CertFixContext,
        )
        mock_ipautil.CalledProcessError = Exception
        mock_ipautil.run.return_value = mock.MagicMock(returncode=0)

        obj = self._make_obj()
        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.RENEWAL_MASTER,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[('sslserver', cert)],
            ipa_certs=[(IPACertType.LDAPS, cert)],
            external_certs=[],
            master_server=None,
        )

        result = obj.run_renewal_master_fix(ctx)
        assert result == 0
        mock_check.assert_called_once()

    @mock.patch(MODULE + '.check_renewed_ipa_certs', return_value=False)
    @mock.patch(MODULE + '.run_cert_fix',
                side_effect=Exception("pki-server failed"))
    @mock.patch(MODULE + '.fix_certreq_directives')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.api')
    def test_ds_cert_expired_no_renewed_files_raises(
        self, mock_api, mock_ipautil, mock_fix_dir,
        mock_run_cf, mock_check,
    ):
        """When DS cert is in list but renewed files DON'T exist, re-raises."""
        from ipaserver.install.ipa_cert_fix import (
            CertFixContext,
        )
        mock_ipautil.CalledProcessError = Exception

        obj = self._make_obj()
        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.RENEWAL_MASTER,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[],
            ipa_certs=[(IPACertType.LDAPS, cert)],
            external_certs=[],
            master_server=None,
        )

        with pytest.raises(Exception, match="pki-server failed"):
            obj.run_renewal_master_fix(ctx)

    @mock.patch(MODULE + '.run_cert_fix',
                side_effect=Exception("pki-server failed"))
    @mock.patch(MODULE + '.fix_certreq_directives')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.api')
    def test_no_ds_cert_pki_error_raises(
        self, mock_api, mock_ipautil, mock_fix_dir, mock_run_cf,
    ):
        """Without DS cert in list, CalledProcessError is NOT tolerated."""
        from ipaserver.install.ipa_cert_fix import (
            CertFixContext,
        )
        mock_ipautil.CalledProcessError = Exception

        obj = self._make_obj()
        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.RENEWAL_MASTER,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[('sslserver', cert)],
            ipa_certs=[(IPACertType.HTTPS, cert)],
            external_certs=[],
            master_server=None,
        )

        with pytest.raises(Exception, match="pki-server failed"):
            obj.run_renewal_master_fix(ctx)


class TestUnitPromoteFullRollbackSequence:
    """Characterization: run_ca_full_promote full rollback sequence."""

    def _make_promote_obj(self):
        from ipaserver.install.ipa_cert_fix import IPACertFix

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = False
        obj._scenario_made_changes = False
        obj._promote_to_renewal_master = mock.MagicMock()
        obj._ca_instance = mock.MagicMock()
        return obj

    def _make_ctx(self):
        from ipaserver.install.ipa_cert_fix import CertFixContext
        return CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.CA_FULL_PROMOTE,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[], ipa_certs=[],
            external_certs=[],
            master_server=None,
        )

    @mock.patch(MODULE + '._find_current_renewal_master',
                return_value='old-master.example.com')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.api')
    def test_unattended_forced_during_rm_fix(
        self, mock_api, mock_ipautil, mock_find_rm,
    ):
        """After user confirms, unattended is set True for RM fix,
        then restored in finally."""
        mock_ipautil.run.return_value = mock.MagicMock(returncode=0)
        mock_ipautil.CalledProcessError = Exception
        mock_api.env.host = 'replica.example.com'

        obj = self._make_promote_obj()
        obj.run_renewal_master_fix = mock.MagicMock(return_value=0)

        unattended_during_fix = []

        def capture_unattended(ctx):
            unattended_during_fix.append(obj.options.unattended)
            return 0

        obj.run_renewal_master_fix.side_effect = capture_unattended

        with mock.patch(MODULE + '.ipautil.user_input', return_value='yes'):
            obj.run_ca_full_promote(self._make_ctx())

        assert unattended_during_fix == [True]
        assert obj.options.unattended is False

    @mock.patch(MODULE + '._find_current_renewal_master',
                return_value='old-master.example.com')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.api')
    def test_rollback_failure_prints_warning(
        self, mock_api, mock_ipautil, mock_find_rm, capsys,
    ):
        """When rollback itself fails, a warning is printed
        (not a crash)."""
        mock_ipautil.run.return_value = mock.MagicMock(returncode=0)
        mock_ipautil.CalledProcessError = Exception
        mock_api.env.host = 'replica.example.com'

        obj = self._make_promote_obj()
        obj.run_renewal_master_fix = mock.MagicMock(
            side_effect=RuntimeError("cert-fix boom"))
        # Rollback calls _ca_instance.set_renewal_master(old_rm) directly
        # (_promote_to_renewal_master is a separate mock).
        # Make the rollback call fail:
        obj._ca_instance.set_renewal_master.side_effect = Exception(
            "LDAP down")

        with mock.patch(MODULE + '.ipautil.user_input', return_value='yes'):
            with pytest.raises(RuntimeError, match="cert-fix boom"):
                obj.run_ca_full_promote(self._make_ctx())

        # Rollback was attempted via _ca_instance.set_renewal_master
        obj._ca_instance.set_renewal_master.assert_called_once_with(
            'old-master.example.com')
        captured = capsys.readouterr()
        assert 'Could not restore renewal master' in captured.out

    @mock.patch(MODULE + '._find_current_renewal_master',
                return_value='old-master.example.com')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.api')
    def test_successful_promote_prints_crl_message(
        self, mock_api, mock_ipautil, mock_find_rm, capsys,
    ):
        """Successful promotion prints CRL generation instructions."""
        mock_ipautil.run.return_value = mock.MagicMock(returncode=0)
        mock_ipautil.CalledProcessError = Exception
        mock_api.env.host = 'replica.example.com'

        obj = self._make_promote_obj()
        obj.run_renewal_master_fix = mock.MagicMock(return_value=0)

        with mock.patch(MODULE + '.ipautil.user_input', return_value='yes'):
            result = obj.run_ca_full_promote(self._make_ctx())

        assert result == 0
        captured = capsys.readouterr()
        assert 'ipa-crlgen-manage enable' in captured.out

    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.api')
    def test_unattended_no_rm_flag_refuses(
        self, mock_api, mock_ipautil,
    ):
        """Unattended mode without --renewal-master refuses promotion."""
        mock_ipautil.run.return_value = mock.MagicMock(returncode=0)
        mock_ipautil.CalledProcessError = Exception
        mock_api.env.host = 'replica.example.com'

        obj = self._make_promote_obj()
        obj.options.unattended = True
        obj.options.renewal_master = False

        result = obj.run_ca_full_promote(self._make_ctx())
        assert result == 1
        obj._promote_to_renewal_master.assert_not_called()


class TestUnitHandleExpiredCaSigningCert:
    """Characterization: _handle_expired_ca_signing_cert paths."""

    def _make_detector(self):
        return DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )

    def test_self_signed_returns_1(self, capsys):
        """Self-signed CA -> directs to ipa-cacert-manage, returns 1."""
        obj = self._make_detector()
        result = obj._handle_expired_ca_signing_cert(
            DeploymentType.CA_SELF_SIGNED)
        assert result == 1
        captured = capsys.readouterr()
        assert 'ipa-cacert-manage renew' in captured.out

    @mock.patch(SMOD + '.get_csr_from_certmonger',
                return_value='AQIDBA==')
    def test_externally_signed_extracts_csr(
        self, mock_get_csr, capsys, tmp_path,
    ):
        """Externally-signed CA -> extracts CSR, returns 1."""
        obj = self._make_detector()

        csr_path = str(tmp_path / 'ca.csr')
        with mock.patch(SMOD + '.paths') as mock_paths:
            mock_paths.IPA_CA_CSR = csr_path
            result = obj._handle_expired_ca_signing_cert(
                DeploymentType.CA_EXTERNALLY_SIGNED)

        assert result == 1
        captured = capsys.readouterr()
        assert 'external-cert-file' in captured.out
        import os
        assert os.path.exists(csr_path)

    @mock.patch(SMOD + '.get_csr_from_certmonger',
                return_value=None)
    def test_externally_signed_no_csr_directs_manual(
        self, mock_get_csr, capsys,
    ):
        """Externally-signed CA, no CSR in certmonger ->
        manual instructions."""
        obj = self._make_detector()
        result = obj._handle_expired_ca_signing_cert(
            DeploymentType.CA_EXTERNALLY_SIGNED)
        assert result == 1
        captured = capsys.readouterr()
        assert 'ipa-cacert-manage renew --external-ca' in captured.out

    def test_ca_less_raises(self):
        """CA-less should never call this -> RuntimeError."""
        obj = self._make_detector()
        with pytest.raises(RuntimeError, match="CA-less"):
            obj._handle_expired_ca_signing_cert(DeploymentType.CA_LESS)


class TestUnitConfirmOrDryRun:
    """Characterization: _confirm_execution behavior."""

    def _make_obj(self, dry_run=False, unattended=False):
        from ipaserver.install.ipa_cert_fix import IPACertFix
        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = dry_run
        obj.options.unattended = unattended
        obj._scenario_made_changes = False
        return obj

    def test_dry_run_returns_false(self, capsys):
        """Dry-run prints plan and returns False."""
        obj = self._make_obj(dry_run=True)
        result = obj._confirm_execution(
            "test label", "proceed",
            dry_extra_lines=["Extra line 1"])
        assert result is False
        assert obj._scenario_made_changes is False
        captured = capsys.readouterr()
        assert '[DRY RUN]' in captured.out
        assert 'Extra line 1' in captured.out

    def test_unattended_returns_true(self):
        """Unattended mode skips prompt, returns True."""
        obj = self._make_obj(unattended=True)
        result = obj._confirm_execution("test", "proceed")
        assert result is True
        assert obj._scenario_made_changes is True

    @mock.patch(MODULE + '.ipautil.user_input', return_value='yes')
    def test_interactive_yes_returns_true(self, mock_input):
        """Interactive mode, user says 'yes' -> True."""
        obj = self._make_obj()
        result = obj._confirm_execution("test", "proceed")
        assert result is True
        assert obj._scenario_made_changes is True

    @mock.patch(MODULE + '.ipautil.user_input', return_value='no')
    def test_interactive_no_returns_false(self, mock_input):
        """Interactive mode, user says 'no' -> False."""
        obj = self._make_obj()
        result = obj._confirm_execution("test", "proceed")
        assert result is False
        assert obj._scenario_made_changes is False


class TestUnitKerberosSetupRestore:
    """Characterization: _setup_kerberos / _restore_kerberos."""

    def test_setup_sets_env_vars(self):
        """_setup_kerberos sets KRB5 env vars and returns old values."""
        from ipaserver.install.ipa_cert_fix import _setup_kerberos
        import os

        old_cc = os.environ.get('KRB5CCNAME')
        old_kt = os.environ.get('KRB5_CLIENT_KTNAME')

        try:
            os.environ['KRB5CCNAME'] = 'FILE:/tmp/old'
            os.environ['KRB5_CLIENT_KTNAME'] = '/old/keytab'

            result = _setup_kerberos()
            assert result == ('FILE:/tmp/old', '/old/keytab')
            assert os.environ['KRB5CCNAME'] == 'MEMORY:'
            assert os.environ['KRB5_CLIENT_KTNAME'] == '/etc/krb5.keytab'
        finally:
            if old_cc is None:
                os.environ.pop('KRB5CCNAME', None)
            else:
                os.environ['KRB5CCNAME'] = old_cc
            if old_kt is None:
                os.environ.pop('KRB5_CLIENT_KTNAME', None)
            else:
                os.environ['KRB5_CLIENT_KTNAME'] = old_kt

    def test_restore_clears_when_originally_unset(self):
        """_restore_kerberos removes vars if they were originally unset."""
        from ipaserver.install.ipa_cert_fix import _restore_kerberos
        import os

        old_cc = os.environ.get('KRB5CCNAME')
        old_kt = os.environ.get('KRB5_CLIENT_KTNAME')

        try:
            os.environ['KRB5CCNAME'] = 'MEMORY:'
            os.environ['KRB5_CLIENT_KTNAME'] = '/etc/krb5.keytab'

            _restore_kerberos((None, None))
            assert 'KRB5CCNAME' not in os.environ
            assert 'KRB5_CLIENT_KTNAME' not in os.environ
        finally:
            if old_cc is not None:
                os.environ['KRB5CCNAME'] = old_cc
            if old_kt is not None:
                os.environ['KRB5_CLIENT_KTNAME'] = old_kt

    def test_restore_preserves_previous_values(self):
        """_restore_kerberos puts back old values."""
        from ipaserver.install.ipa_cert_fix import _restore_kerberos
        import os

        old_cc = os.environ.get('KRB5CCNAME')
        old_kt = os.environ.get('KRB5_CLIENT_KTNAME')

        try:
            os.environ['KRB5CCNAME'] = 'MEMORY:'
            os.environ['KRB5_CLIENT_KTNAME'] = '/etc/krb5.keytab'

            _restore_kerberos(('FILE:/tmp/prev', '/prev/keytab'))
            assert os.environ['KRB5CCNAME'] == 'FILE:/tmp/prev'
            assert os.environ['KRB5_CLIENT_KTNAME'] == '/prev/keytab'
        finally:
            if old_cc is None:
                os.environ.pop('KRB5CCNAME', None)
            else:
                os.environ['KRB5CCNAME'] = old_cc
            if old_kt is None:
                os.environ.pop('KRB5_CLIENT_KTNAME', None)
            else:
                os.environ['KRB5_CLIENT_KTNAME'] = old_kt


class TestUnitCertCriteria:
    """Characterization: _cert_criteria for all cert types."""

    @mock.patch(SMOD + '.paths')
    def test_https_criteria(self, mock_paths):
        """HTTPS -> cert-file criteria."""
        mock_paths.HTTPD_CERT_FILE = '/etc/pki/tls/certs/httpd.crt'
        ctx = mock.MagicMock()
        result = ExternalCertHandler._cert_criteria(IPACertType.HTTPS, ctx)
        assert result == {'cert-file': '/etc/pki/tls/certs/httpd.crt'}

    @mock.patch(SMOD + '.paths')
    def test_kdc_criteria(self, mock_paths):
        """KDC -> cert-file criteria."""
        mock_paths.KDC_CERT = '/var/kerberos/krb5kdc/kdc.crt'
        ctx = mock.MagicMock()
        result = ExternalCertHandler._cert_criteria(IPACertType.KDC, ctx)
        assert result == {'cert-file': '/var/kerberos/krb5kdc/kdc.crt'}

    def test_ldaps_criteria(self):
        """LDAPS -> cert-database + cert-nickname criteria."""
        ctx = mock.MagicMock()
        ctx.ds_dbdir = '/etc/dirsrv/slapd-EXAMPLE'
        ctx.ds_nickname = 'Server-Cert'
        result = ExternalCertHandler._cert_criteria(IPACertType.LDAPS, ctx)
        assert result == {
            'cert-database': '/etc/dirsrv/slapd-EXAMPLE',
            'cert-nickname': 'Server-Cert',
        }

    @mock.patch(SMOD + '.paths')
    def test_ipara_criteria(self, mock_paths):
        """IPARA -> cert-file criteria."""
        mock_paths.RA_AGENT_PEM = '/etc/pki/ra-agent.pem'
        ctx = mock.MagicMock()
        result = ExternalCertHandler._cert_criteria(IPACertType.IPARA, ctx)
        assert result == {'cert-file': '/etc/pki/ra-agent.pem'}


class TestUnitTrackingParams:
    """Characterization: _tracking_params for each cert type."""

    @mock.patch(SMOD + '.ipa_certs')
    @mock.patch(SMOD + '.IPA_CA_RECORD', 'ipa-ca')
    @mock.patch(SMOD + '.paths')
    @mock.patch(SMOD + '.api')
    def test_https_params(self, mock_api, mock_paths, mock_certs):
        """HTTPS params include dns, principal, post_command."""
        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'
        mock_api.env.domain = 'example.com'
        mock_paths.HTTPD_CERT_FILE = '/etc/pki/tls/certs/httpd.crt'
        mock_paths.HTTPD_KEY_FILE = '/etc/pki/tls/private/httpd.key'
        mock_paths.HTTPD_PASSWD_FILE_FMT = '/var/lib/ipa/passwds/{host}'
        mock_certs.get_default_profile.return_value = 'caIPAserviceCert'

        ctx = mock.MagicMock()
        ctx.subject_base = 'O=EXAMPLE.COM'
        params = ExternalCertHandler._tracking_params(IPACertType.HTTPS, ctx)

        assert params['ca'] == 'IPA'
        assert params['storage'] == 'FILE'
        assert params['post_command'] == 'restart_httpd'
        assert 'server.example.com' in params['dns']
        assert params['principal'] == 'HTTP/server.example.com@EXAMPLE.COM'

    @mock.patch(SMOD + '.ipa_certs')
    @mock.patch(SMOD + '.paths')
    @mock.patch(SMOD + '.api')
    def test_ldaps_params(self, mock_api, mock_paths, mock_certs):
        """LDAPS params use NSSDB storage with ds_dbdir."""
        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'
        mock_certs.get_default_profile.return_value = 'caIPAserviceCert'

        ctx = mock.MagicMock()
        ctx.subject_base = 'O=EXAMPLE.COM'
        ctx.ds_dbdir = '/etc/dirsrv/slapd-EXAMPLE-COM'
        ctx.ds_nickname = 'Server-Cert'
        ctx.serverid = 'EXAMPLE-COM'
        params = ExternalCertHandler._tracking_params(IPACertType.LDAPS, ctx)

        assert params['storage'] == 'NSSDB'
        assert params['certpath'] == '/etc/dirsrv/slapd-EXAMPLE-COM'
        assert params['nickname'] == 'Server-Cert'

    @mock.patch(SMOD + '.KDC_PROFILE', 'KDCs_PKINIT_Certs')
    @mock.patch(SMOD + '.paths')
    @mock.patch(SMOD + '.api')
    def test_kdc_params(self, mock_api, mock_paths):
        """KDC params use KDC_PROFILE and krbtgt principal."""
        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'
        mock_paths.KDC_CERT = '/var/kerberos/krb5kdc/kdc.crt'
        mock_paths.KDC_KEY = '/var/kerberos/krb5kdc/kdc.key'

        ctx = mock.MagicMock()
        ctx.subject_base = 'O=EXAMPLE.COM'
        params = ExternalCertHandler._tracking_params(IPACertType.KDC, ctx)

        assert params['profile'] == 'KDCs_PKINIT_Certs'
        assert params['principal'] == 'krbtgt/EXAMPLE.COM@EXAMPLE.COM'
        assert params['post_command'] == 'renew_kdc_cert'

    @mock.patch(SMOD + '.api')
    def test_ipara_returns_none(self, mock_api):
        """IPARA has no tracking params (fetched from LDAP)."""
        mock_api.env.host = 'server.example.com'
        ctx = mock.MagicMock()
        ctx.subject_base = 'O=EXAMPLE.COM'
        result = ExternalCertHandler._tracking_params(IPACertType.IPARA, ctx)
        assert result is None


class TestUnitIsCertValid:
    """Characterization: _is_cert_valid checks cert expiry."""

    @mock.patch(SMOD + '.x509')
    def test_valid_file_cert(self, mock_x509):
        """File-based cert that is not near expiry -> True."""
        import datetime as dt

        client = object.__new__(CertmongerClient)
        client.get_request_value = mock.MagicMock(
            side_effect=lambda rid, k: {
                'cert-file': '/etc/pki/tls/certs/httpd.crt',
                'cert-database': None,
                'cert-nickname': None,
            }.get(k))

        cert = mock.MagicMock()
        cert.not_valid_after_utc = dt.datetime(
            2030, 1, 1, tzinfo=dt.timezone.utc)
        mock_x509.load_certificate_from_file.return_value = cert

        assert client.is_cert_valid('req1') is True

    @mock.patch(SMOD + '.x509')
    def test_expired_file_cert(self, mock_x509):
        """File-based cert that is expired -> False."""
        import datetime as dt

        client = object.__new__(CertmongerClient)
        client.get_request_value = mock.MagicMock(
            side_effect=lambda rid, k: {
                'cert-file': '/etc/pki/tls/certs/httpd.crt',
                'cert-database': None,
                'cert-nickname': None,
            }.get(k))

        cert = mock.MagicMock()
        cert.not_valid_after_utc = dt.datetime(
            2020, 1, 1, tzinfo=dt.timezone.utc)
        mock_x509.load_certificate_from_file.return_value = cert

        assert client.is_cert_valid('req1') is False

    def test_no_cert_location_returns_false(self):
        """No cert-file or cert-database -> False."""
        client = object.__new__(CertmongerClient)
        client.get_request_value = mock.MagicMock(return_value=None)
        assert client.is_cert_valid('req1') is False


class TestUnitReplaceCertInNssdb:
    """Characterization: _replace_cert_in_nssdb."""

    @mock.patch(SMOD + '.ipautil')
    def test_replaces_existing_cert(self, mock_ipautil):
        """Deletes old cert and adds new one."""
        from ipaserver.install.ipa_cert_fix import _replace_cert_in_nssdb

        db = mock.MagicMock()
        cert = mock.MagicMock()

        _replace_cert_in_nssdb(db, 'Server-Cert', cert)
        db.delete_cert.assert_called_once_with('Server-Cert')
        db.add_cert.assert_called_once()

    @mock.patch(SMOD + '.ipautil')
    def test_handles_missing_cert_on_delete(self, mock_ipautil):
        """CalledProcessError on delete (cert not found) is ignored."""
        from ipaserver.install.ipa_cert_fix import _replace_cert_in_nssdb

        mock_ipautil.CalledProcessError = Exception
        db = mock.MagicMock()
        db.delete_cert.side_effect = Exception("not found")
        cert = mock.MagicMock()

        _replace_cert_in_nssdb(db, 'Server-Cert', cert)
        db.add_cert.assert_called_once()


class TestUnitUpdateCsCfg:
    """Characterization: _update_cs_cfg updates Dogtag config."""

    @mock.patch(SMOD + '.directivesetter')
    @mock.patch(SMOD + '.os.path.exists', return_value=True)
    @mock.patch(SMOD + '.x509')
    def test_updates_subsystem_directive(
        self, mock_x509, mock_exists, mock_ds,
    ):
        """Subsystem cert updates ca.subsystem.cert in CA CS.cfg."""
        from ipaserver.install.ipa_cert_fix import _update_cs_cfg

        cert = mock.MagicMock()
        cert.public_bytes.return_value = b'\x01\x02\x03'
        mock_x509.Encoding.DER = 'DER'

        _update_cs_cfg('subsystemCert cert-pki-ca', cert)

        mock_ds.set_directive.assert_called_once()
        call_args = mock_ds.set_directive.call_args
        assert call_args[0][1] == 'ca.subsystem.cert'

    @mock.patch(SMOD + '.directivesetter')
    @mock.patch(SMOD + '.os.path.exists', return_value=True)
    @mock.patch(SMOD + '.x509')
    def test_kra_transport_updates_connector(
        self, mock_x509, mock_exists, mock_ds,
    ):
        """KRA transport cert also updates ca.connector.KRA.transportCert."""
        from ipaserver.install.ipa_cert_fix import _update_cs_cfg

        cert = mock.MagicMock()
        cert.public_bytes.return_value = b'\x01\x02\x03'
        mock_x509.Encoding.DER = 'DER'

        _update_cs_cfg('transportCert cert-pki-kra', cert)

        # Should be called twice: once for kra.transport.cert,
        # once for ca.connector.KRA.transportCert
        assert mock_ds.set_directive.call_count == 2

    def test_unknown_nickname_is_noop(self):
        """Nickname not in _CS_CFG_CERT_DIRECTIVES -> no-op."""
        from ipaserver.install.ipa_cert_fix import _update_cs_cfg
        cert = mock.MagicMock()
        # Should not raise
        _update_cs_cfg('Server-Cert cert-pki-ca', cert)


class TestUnitEnsureLdapConnected:
    """Characterization: _ensure_ldap_connected unconditional reconnect."""

    @mock.patch(SMOD + '.api')
    def test_disconnects_and_reconnects(self, mock_api):
        """Always disconnects then connects, regardless of state."""
        from ipaserver.install.ipa_cert_fix import (
            _ensure_ldap_connected,
        )
        mock_api.Backend.ldap2.isconnected.return_value = True

        _ensure_ldap_connected()

        mock_api.Backend.ldap2.disconnect.assert_called_once()
        mock_api.Backend.ldap2.connect.assert_called_once()

    @mock.patch(SMOD + '.api')
    def test_handles_disconnect_error(self, mock_api):
        """Disconnect error is swallowed, connect still called."""
        from ipaserver.install.ipa_cert_fix import (
            _ensure_ldap_connected,
        )
        mock_api.Backend.ldap2.isconnected.return_value = True
        mock_api.Backend.ldap2.disconnect.side_effect = Exception("broken")

        _ensure_ldap_connected()
        mock_api.Backend.ldap2.connect.assert_called_once()

    @mock.patch(SMOD + '.api')
    def test_skips_disconnect_if_not_connected(self, mock_api):
        """If not connected, skips disconnect."""
        from ipaserver.install.ipa_cert_fix import (
            _ensure_ldap_connected,
        )
        mock_api.Backend.ldap2.isconnected.return_value = False

        _ensure_ldap_connected()
        mock_api.Backend.ldap2.disconnect.assert_not_called()
        mock_api.Backend.ldap2.connect.assert_called_once()


class TestUnitRestoreHelper:
    """Characterization: _restore_helper retries on failure."""

    def test_successful_restore(self):
        """Normal case: restores helper in one call."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        obj = CertRenewalFromMaster(mock.MagicMock(), 'master')
        obj._restore_helper('/usr/libexec/ipa/ipa-submit')
        obj._cm.restore_ca_override.assert_called_once_with(
            'IPA', '/usr/libexec/ipa/ipa-submit')

    @mock.patch(SMOD + '.time.sleep')
    @mock.patch(SMOD + '.time.monotonic')
    def test_timeout_prints_critical(
        self, mock_mono, mock_sleep, capsys,
    ):
        """After timeout, prints CRITICAL message."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        obj = CertRenewalFromMaster(mock.MagicMock(), 'master')
        obj._cm.restore_ca_override.side_effect = Exception("D-Bus down")
        mock_mono.side_effect = [0, 0, 200]

        obj._restore_helper('/usr/libexec/ipa/ipa-submit', timeout=1)

        captured = capsys.readouterr()
        assert 'CRITICAL' in captured.out
        assert 'getcert modify-ca' in captured.out


class TestUnitRunExternalCertsDryRun:
    """Characterization: run_external_certs dry-run path."""

    def test_dry_run_returns_zero(self, capsys):
        """Dry-run lists CSR paths and exits 0."""
        from ipaserver.install.ipa_cert_fix import (
            IPACertFix, CertFixContext,
        )

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = True

        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_LESS_EXTERNAL,
            scenario=FixScenario.EXTERNAL_CERTS,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[],
            ipa_certs=[],
            external_certs=[(IPACertType.HTTPS, cert)],
            master_server=None,
        )

        result = obj.run_external_certs(ctx)
        assert result == 0
        captured = capsys.readouterr()
        assert '[DRY RUN]' in captured.out
        assert 'HTTPS' in captured.out

    def test_no_external_certs_nothing_to_do(self, capsys):
        """No external certs -> 'Nothing to do', exit 0."""
        from ipaserver.install.ipa_cert_fix import (
            IPACertFix, CertFixContext,
        )

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False

        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_LESS_EXTERNAL,
            scenario=FixScenario.EXTERNAL_CERTS,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[], ipa_certs=[],
            external_certs=[],
            master_server=None,
        )

        result = obj.run_external_certs(ctx)
        assert result == 0


class TestUnitCheckTcpReachable:
    """Characterization: _check_tcp_reachable."""

    @mock.patch(SMOD + '.socket')
    def test_dns_failure_raises(self, mock_socket):
        """DNS resolution failure -> RuntimeError."""
        import socket as real_socket
        mock_socket.gaierror = real_socket.gaierror
        mock_socket.getaddrinfo.side_effect = real_socket.gaierror(
            "Name or service not known")
        mock_socket.AF_UNSPEC = real_socket.AF_UNSPEC
        mock_socket.SOCK_STREAM = real_socket.SOCK_STREAM

        with pytest.raises(RuntimeError, match="Cannot resolve"):
            _check_tcp_reachable('nonexistent.example.com')

    @mock.patch(SMOD + '.socket')
    def test_all_addrs_unreachable_raises(self, mock_socket):
        """All addresses fail -> RuntimeError."""
        import socket as real_socket
        mock_socket.AF_UNSPEC = real_socket.AF_UNSPEC
        mock_socket.SOCK_STREAM = real_socket.SOCK_STREAM
        mock_socket.getaddrinfo.return_value = [
            (real_socket.AF_INET, real_socket.SOCK_STREAM, 0, '',
             ('1.2.3.4', 443)),
        ]
        sock_inst = mock.MagicMock()
        sock_inst.connect.side_effect = OSError("refused")
        mock_socket.socket.return_value = sock_inst

        with pytest.raises(RuntimeError, match="Cannot connect"):
            _check_tcp_reachable('down.example.com')


class TestUnitResolveTrackingRequests:
    """Characterization: _resolve_tracking_requests."""

    def test_missing_request_skipped(self):
        """If certmonger has no tracking for a cert, it's skipped."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        cm = mock.MagicMock()
        cm.get_request_id.return_value = None
        obj = CertRenewalFromMaster(cm, 'master')

        tracking = [
            ('sslserver', mock.MagicMock(),
             {'cert-nickname': 'Server-Cert'}, lambda: None),
        ]
        result = obj._resolve_tracking_requests(tracking)
        assert result == []

    def test_found_request_included(self):
        """Found tracking request is included with original CA."""
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster

        cm = mock.MagicMock()
        cm.get_request_id.return_value = 'req-42'
        cm.get_request_value.return_value = ('dogtag-ipa-ca-renew-agent')
        obj = CertRenewalFromMaster(cm, 'master')

        cert = mock.MagicMock()

        def loader():
            return None
        tracking = [
            ('sslserver', cert, {'cert-nickname': 'Server-Cert'}, loader),
        ]
        result = obj._resolve_tracking_requests(tracking)
        assert len(result) == 1
        desc, _old_cert, req_id, orig_ca, _load_fn = result[0]
        assert desc == 'sslserver'
        assert req_id == 'req-42'
        assert orig_ca == 'dogtag-ipa-ca-renew-agent'


class TestUnitCheckIsRenewalMaster:
    """Characterization: check_is_renewal_master error handling."""

    def test_returns_true_when_rm(self):
        ca_inst = mock.MagicMock()
        ca_inst.is_renewal_master.return_value = True
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=ca_inst,
            options=mock.MagicMock(),
        )
        assert obj.check_is_renewal_master() is True

    def test_returns_false_when_not_rm(self):
        ca_inst = mock.MagicMock()
        ca_inst.is_renewal_master.return_value = False
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=ca_inst,
            options=mock.MagicMock(),
        )
        assert obj.check_is_renewal_master() is False

    def test_none_ca_instance_raises(self):
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=None,
            options=mock.MagicMock(),
        )
        with pytest.raises(RuntimeError, match="CA instance"):
            obj.check_is_renewal_master()

    def test_network_error_returns_false(self):
        from ipalib import errors
        ca_inst = mock.MagicMock()
        ca_inst.is_renewal_master.side_effect = (
            errors.NetworkError(message="conn refused"))
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=ca_inst,
            options=mock.MagicMock(),
        )
        assert obj.check_is_renewal_master() is False

    def test_unexpected_error_returns_false(self):
        ca_inst = mock.MagicMock()
        ca_inst.is_renewal_master.side_effect = (ValueError("unexpected"))
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=ca_inst,
            options=mock.MagicMock(),
        )
        assert obj.check_is_renewal_master() is False


class TestUnitWarnCaChainNearExpiry:
    """Characterization: _warn_ca_chain_near_expiry."""

    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_warns_near_expiry(self, mock_paths, mock_x509, capsys):
        import datetime as dt

        mock_paths.IPA_CA_CRT = '/etc/ipa/ca.crt'
        near_cert = mock.MagicMock()
        near_cert.not_valid_after_utc = dt.datetime(
            2026, 4, 25, tzinfo=dt.timezone.utc)
        near_cert.subject = 'CN=CA'
        mock_x509.load_certificate_list_from_file.return_value = [near_cert]

        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )
        obj._warn_ca_chain_near_expiry()

        captured = capsys.readouterr()
        assert 'WARNING' in captured.out
        assert 'ipa-cacert-manage' in captured.out

    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_no_warning_for_valid_chain(
        self, mock_paths, mock_x509, capsys,
    ):
        import datetime as dt

        mock_paths.IPA_CA_CRT = '/etc/ipa/ca.crt'
        valid_cert = mock.MagicMock()
        valid_cert.not_valid_after_utc = dt.datetime(
            2030, 1, 1, tzinfo=dt.timezone.utc)
        mock_x509.load_certificate_list_from_file.return_value = [valid_cert]

        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )
        obj._warn_ca_chain_near_expiry()

        captured = capsys.readouterr()
        assert 'WARNING' not in captured.out

    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.paths')
    def test_file_missing_no_crash(self, mock_paths, mock_x509):
        mock_paths.IPA_CA_CRT = '/etc/ipa/ca.crt'
        mock_x509.load_certificate_list_from_file.side_effect = Exception()

        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )
        obj._warn_ca_chain_near_expiry()  # should not raise


class TestUnitKillStuckHelpers:
    """Characterization: _kill_stuck_helpers."""

    @mock.patch(SMOD + '.time.sleep')
    @mock.patch(SMOD + '.ipautil')
    def test_kills_both_processes(self, mock_ipautil, mock_sleep):
        from ipaserver.install.ipa_cert_fix import _kill_stuck_helpers
        mock_ipautil.run.return_value = mock.MagicMock(returncode=0)
        _kill_stuck_helpers()
        assert mock_ipautil.run.call_count == 2
        calls = [c[0][0] for c in mock_ipautil.run.call_args_list]
        assert any('ipa-submit' in str(c) for c in calls)
        assert any('ipa-server-guard' in str(c) for c in calls)

    @mock.patch(SMOD + '.time.sleep')
    @mock.patch(SMOD + '.ipautil')
    def test_pkill_failure_ignored(self, mock_ipautil, mock_sleep):
        from ipaserver.install.ipa_cert_fix import _kill_stuck_helpers
        mock_ipautil.run.side_effect = Exception("pkill not found")
        _kill_stuck_helpers()  # should not raise


class TestUnitDetectAndDispatchScenarioPath:
    """Characterization: _classify_and_dispatch full scenario dispatch."""

    @mock.patch(MODULE + '.print_intentions')
    @mock.patch(MODULE + '.ca')
    @mock.patch(MODULE + '.cainstance')
    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid', return_value='EXAMPLE-COM')
    @mock.patch(MODULE + '.api')
    def test_dispatches_to_scenario_handler(
        self, mock_api, mock_r2s, mock_ds, mock_cai,
        mock_ca_mod, mock_pi,
    ):
        """With expired certs, dispatches to the correct handler."""
        from ipaserver.install.ipa_cert_fix import IPACertFix

        mock_api.env.realm = 'EXAMPLE.COM'
        mock_cai.is_ca_installed_locally.return_value = False
        ds_inst = mock.MagicMock()
        ds_inst.find_subject_base.return_value = 'O=EXAMPLE.COM'
        ds_inst.get_server_cert_nickname.return_value = 'Server-Cert'
        mock_ds.DsInstance.return_value = ds_inst
        mock_ds.config_dirname.return_value = '/etc/dirsrv/slapd-X/'

        cert = mock.MagicMock()
        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = True
        obj._ca_instance = None
        obj._scenario_made_changes = False
        obj._cm = mock.MagicMock()

        handler = mock.MagicMock(return_value=0)
        obj.run_external_certs = handler

        with mock.patch.object(
            DeploymentDetector, 'detect_deployment_type',
            return_value=DeploymentType.CA_LESS_EXTERNAL,
        ), mock.patch.object(
            DeploymentDetector, '_classify_certs',
            return_value=([], [], [(IPACertType.HTTPS, cert)]),
        ), mock.patch.object(
            DeploymentDetector, 'determine_scenario',
            return_value=(FixScenario.EXTERNAL_CERTS, None),
        ):
            result = obj._classify_and_dispatch()
        assert result == 0
        handler.assert_called_once()

    @mock.patch(MODULE + '.print_intentions')
    @mock.patch(MODULE + '.ca')
    @mock.patch(MODULE + '.cainstance')
    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid', return_value='EXAMPLE-COM')
    @mock.patch(MODULE + '.api')
    def test_scenario_runtime_error_returns_1(
        self, mock_api, mock_r2s, mock_ds, mock_cai,
        mock_ca_mod, mock_pi,
    ):
        """RuntimeError from determine_scenario -> exit 1."""
        from ipaserver.install.ipa_cert_fix import IPACertFix

        mock_api.env.realm = 'EXAMPLE.COM'
        mock_cai.is_ca_installed_locally.return_value = False
        ds_inst = mock.MagicMock()
        ds_inst.find_subject_base.return_value = 'O=EXAMPLE.COM'
        ds_inst.get_server_cert_nickname.return_value = 'Server-Cert'
        mock_ds.DsInstance.return_value = ds_inst
        mock_ds.config_dirname.return_value = '/etc/dirsrv/slapd-X/'

        cert = mock.MagicMock()
        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = True
        obj._ca_instance = None
        obj._scenario_made_changes = False
        obj._cm = mock.MagicMock()

        with mock.patch.object(
            DeploymentDetector, 'detect_deployment_type',
            return_value=DeploymentType.CA_LESS,
        ), mock.patch.object(
            DeploymentDetector, '_classify_certs',
            return_value=([], [(IPACertType.HTTPS, cert)], []),
        ), mock.patch.object(
            DeploymentDetector, 'determine_scenario',
            side_effect=RuntimeError("No server"),
        ):
            result = obj._classify_and_dispatch()
        assert result == 1


class TestUnitResubmitCertViaMaster:
    """Characterization: _resubmit core flow."""

    def _make_obj(self):
        from ipaserver.install.ipa_cert_fix import CertRenewalFromMaster
        cm = mock.MagicMock()
        cm.is_cert_valid.return_value = False
        cm.is_responsive.return_value = True
        obj = CertRenewalFromMaster(cm, 'master.example.com')
        return obj

    @mock.patch(SMOD + '._kill_stuck_helpers')
    @mock.patch(SMOD + '.print_cert_info')
    @mock.patch(SMOD + '.ipautil')
    @mock.patch(SMOD + '.api')
    def test_ipa_cert_resubmit(
        self, mock_api, mock_ipautil, mock_pci, mock_ksh,
    ):
        """IPA cert (IPACertType) resubmits without CA switch."""
        import datetime as dt

        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'

        obj = self._make_obj()
        obj._cm.wait_for_request.return_value = 'MONITORING'
        obj._cm.get_request_value.return_value = 'IPA'
        mock_ipautil.run.return_value = mock.MagicMock()

        old_cert = mock.MagicMock()
        old_cert.serial_number = 100
        new_cert = mock.MagicMock()
        new_cert.serial_number = 200
        new_cert.not_valid_before_utc = dt.datetime(
            2026, 1, 1, tzinfo=dt.timezone.utc)
        new_cert.not_valid_after_utc = dt.datetime(
            2028, 1, 1, tzinfo=dt.timezone.utc)
        loader = mock.MagicMock(return_value=new_cert)

        obj._resubmit(IPACertType.HTTPS, old_cert, 'req-1', 'IPA', loader)

        # Should NOT switch CA for IPA certs
        obj._cm.resubmit_request.assert_called_once_with(
            'req-1', ca=None, profile=None)

    @mock.patch(SMOD + '._kill_stuck_helpers')
    @mock.patch(SMOD + '.print_cert_info')
    @mock.patch(SMOD + '.ipautil')
    @mock.patch(SMOD + '.api')
    def test_dogtag_cert_switches_ca_and_adds_principal(
        self, mock_api, mock_ipautil, mock_pci, mock_ksh,
    ):
        """Dogtag cert (string) switches CA to IPA and adds principal."""
        import datetime as dt

        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'

        obj = self._make_obj()
        obj._cm.wait_for_request.return_value = 'MONITORING'
        obj._cm.get_request_value.side_effect = lambda rid, k: {
            'template-principal': None,
            'template-profile': 'caServerCert',
            'ca-name': 'dogtag-ipa-ca-renew-agent',
        }.get(k)
        mock_ipautil.run.return_value = mock.MagicMock()

        old_cert = mock.MagicMock()
        old_cert.serial_number = 100
        new_cert = mock.MagicMock()
        new_cert.serial_number = 200
        new_cert.not_valid_before_utc = dt.datetime(
            2026, 1, 1, tzinfo=dt.timezone.utc)
        new_cert.not_valid_after_utc = dt.datetime(
            2028, 1, 1, tzinfo=dt.timezone.utc)
        loader = mock.MagicMock(return_value=new_cert)

        desc = DOGTAG_CERTS['sslserver']
        obj._resubmit(
            desc, old_cert, 'req-2',
            'dogtag-ipa-ca-renew-agent', loader)

        # Should switch CA to IPA for dogtag certs
        obj._cm.resubmit_request.assert_called_once_with(
            'req-2', ca='IPA', profile='caIPAserviceCert')
        # Should add host principal
        obj._cm.add_principal.assert_called_once_with(
            'req-2', 'host/server.example.com@EXAMPLE.COM')
        # Original principal saved for restore
        assert 'req-2' in obj._original_principals

    @mock.patch(SMOD + '._kill_stuck_helpers')
    @mock.patch(SMOD + '.print_cert_info')
    @mock.patch(SMOD + '.api')
    def test_timeout_raises(self, mock_api, mock_pci, mock_ksh):
        """Timeout waiting for MONITORING -> RuntimeError."""
        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'

        obj = self._make_obj()
        obj._cm.wait_for_request.side_effect = RuntimeError("timeout")
        obj._cm.get_request_value.return_value = 'IPA'

        old_cert = mock.MagicMock()
        old_cert.serial_number = 100

        with pytest.raises(RuntimeError, match="timed out"):
            obj._resubmit(
                IPACertType.HTTPS, old_cert, 'req-1', 'IPA',
                lambda: None)

    @mock.patch(SMOD + '._kill_stuck_helpers')
    @mock.patch(SMOD + '.print_cert_info')
    @mock.patch(SMOD + '.api')
    def test_wrong_state_raises(self, mock_api, mock_pci, mock_ksh):
        """Non-MONITORING state -> RuntimeError with ca-error."""
        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'

        obj = self._make_obj()
        obj._cm.wait_for_request.return_value = 'CA_REJECTED'
        obj._cm.get_request_value.side_effect = lambda rid, k: {
            'ca-error': 'ACL denied',
            'ca-name': 'IPA',
        }.get(k)

        old_cert = mock.MagicMock()
        old_cert.serial_number = 100

        with pytest.raises(RuntimeError, match="CA_REJECTED"):
            obj._resubmit(
                IPACertType.HTTPS, old_cert, 'req-1', 'IPA',
                lambda: None)

    @mock.patch(SMOD + '._kill_stuck_helpers')
    @mock.patch(SMOD + '.print_cert_info')
    @mock.patch(SMOD + '.ipautil')
    @mock.patch(SMOD + '.certmonger')
    @mock.patch(SMOD + '.api')
    def test_already_valid_skips(
        self, mock_api, mock_cm, mock_ipautil, mock_pci,
        mock_ksh, capsys,
    ):
        """Cert already valid -> skips resubmit."""
        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'

        obj = self._make_obj()
        obj._cm.is_cert_valid.return_value = True
        old_cert = mock.MagicMock()
        old_cert.serial_number = 100

        obj._resubmit(IPACertType.HTTPS, old_cert, 'req-1', 'IPA', lambda: None)

        mock_cm.resubmit_request.assert_not_called()
        captured = capsys.readouterr()
        assert 'already has a valid cert' in captured.out


class TestUnitExpiredDogtagCerts:
    """Characterization: expired_dogtag_certs module-level function."""

    @mock.patch(SMOD + '._get_pki_nssdb')
    def test_returns_expired_certs(self, mock_nssdb):
        import datetime as dt
        from ipaserver.install.ipa_cert_fix import expired_dogtag_certs

        now = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        expired = dt.datetime(2029, 6, 1, tzinfo=dt.timezone.utc)
        valid = dt.datetime(2031, 1, 1, tzinfo=dt.timezone.utc)

        def get_cert(nickname):
            cert = mock.MagicMock()
            if 'caSigningCert' in nickname:
                cert.not_valid_after_utc = expired
            else:
                cert.not_valid_after_utc = valid
            return cert

        mock_nssdb.return_value.get_cert.side_effect = get_cert

        result = expired_dogtag_certs(now)
        expired_ids = [cid for cid, _ in result]
        assert 'ca_issuing' in expired_ids
        # Valid certs should not be in the list
        assert 'sslserver' not in expired_ids

    @mock.patch(SMOD + '._get_pki_nssdb')
    def test_missing_cert_skipped(self, mock_nssdb):
        import datetime as dt
        from ipaserver.install.ipa_cert_fix import expired_dogtag_certs

        now = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        mock_nssdb.return_value.get_cert.side_effect = RuntimeError("not found")

        result = expired_dogtag_certs(now)
        assert result == []


class TestUnitPrintIntentions:
    """Characterization: print_intentions output."""

    def test_prints_dogtag_and_ipa(self, capsys):
        from ipaserver.install.ipa_cert_fix import print_intentions

        cert = mock.MagicMock()
        cert.subject = 'CN=CA'
        cert.serial_number = 42
        cert.not_valid_after_utc = '2026-01-01'

        print_intentions(
            [('sslserver', cert)],
            [(IPACertType.HTTPS, cert)],
        )
        captured = capsys.readouterr()
        assert 'will be renewed' in captured.out
        assert 'sslserver' in captured.out
        assert 'HTTPS' in captured.out

    def test_prints_external_separately(self, capsys):
        from ipaserver.install.ipa_cert_fix import print_intentions

        cert = mock.MagicMock()
        cert.subject = 'CN=ext'
        cert.serial_number = 99
        cert.not_valid_after_utc = '2026-01-01'

        print_intentions([], [], [(IPACertType.KDC, cert)])
        captured = capsys.readouterr()
        assert 'externally-signed' in captured.out
        assert 'KDC' in captured.out

    def test_no_certs_no_output(self, capsys):
        from ipaserver.install.ipa_cert_fix import print_intentions
        print_intentions([], [])
        captured = capsys.readouterr()
        assert captured.out == ''


class TestUnitGetCsrFromCertmonger:
    """Characterization: get_csr_from_certmonger."""

    @mock.patch(SMOD + '.certmonger')
    def test_no_request_returns_none(self, mock_cm):
        from ipaserver.install.ipa_cert_fix import get_csr_from_certmonger
        mock_cm.get_request_id.return_value = None
        assert get_csr_from_certmonger('Server-Cert') is None

    @mock.patch(SMOD + '.certmonger')
    def test_no_csr_returns_none(self, mock_cm):
        from ipaserver.install.ipa_cert_fix import get_csr_from_certmonger
        mock_cm.get_request_id.return_value = 'req-1'
        mock_cm.get_request_value.return_value = None
        assert get_csr_from_certmonger('Server-Cert') is None


class TestUnitFindCurrentRenewalMaster:
    """Characterization: _find_current_renewal_master."""

    @mock.patch(SMOD + '.api')
    def test_returns_fqdn(self, mock_api):
        from ipaserver.install.ipa_cert_fix import (
            _find_current_renewal_master,
        )
        from ipapython.dn import DN

        mock_api.env.container_masters = 'cn=masters,cn=ipa,cn=etc'
        mock_api.env.basedn = 'dc=example,dc=com'

        entry = mock.MagicMock()
        entry.dn = DN('cn=CA,cn=master.example.com,cn=masters,'
                      'cn=ipa,cn=etc,dc=example,dc=com')
        mock_api.Backend.ldap2.get_entries.return_value = [entry]

        result = _find_current_renewal_master()
        assert result == 'master.example.com'

    @mock.patch(SMOD + '.api')
    def test_ldap_error_returns_none(self, mock_api):
        from ipaserver.install.ipa_cert_fix import (
            _find_current_renewal_master,
        )
        mock_api.env.container_masters = 'cn=masters'
        mock_api.env.basedn = 'dc=example'
        mock_api.Backend.ldap2.get_entries.side_effect = Exception("fail")
        assert _find_current_renewal_master() is None


class TestUnitFixRaSubsystemMismatches:
    """Characterization: _fix_ra_subsystem_mismatches."""

    @mock.patch(SMOD + '.cainstance')
    @mock.patch(SMOD + '.NSSDatabase')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.api')
    def test_updates_local_file_and_ldap(
        self, mock_api, mock_x509, mock_nssdb, mock_cai, capsys,
    ):
        """Mismatch with update_desc -> updates LDAP description."""

        newest = mock.MagicMock()
        newest.serial_number = 42
        entry = mock.MagicMock()
        conn = mock.MagicMock()
        mock_api.Backend.ldap2 = conn

        mismatches = [{
            'label': 'IPA RA',
            'newest': newest,
            'dn': 'uid=ipara,ou=people,o=ipaca',
            'entry': entry,
            'update_local': False,
            'update_ldap_cert': False,
            'update_desc': True,
            'path_info': ('file', '/etc/pki/ra-agent.pem'),
            'expected_desc': '2;42;CN=CA;CN=RA',
        }]

        DeploymentDetector._fix_ra_subsystem_mismatches(mismatches)

        conn.update_entry.assert_called_once_with(entry)
        entry.__setitem__.assert_called_with('description', '2;42;CN=CA;CN=RA')

    @mock.patch(SMOD + '.cainstance')
    @mock.patch(SMOD + '.x509')
    @mock.patch(SMOD + '.api')
    def test_updates_local_file(
        self, mock_api, mock_x509, mock_cai, capsys,
    ):
        """Mismatch with update_local on file -> writes cert file."""

        newest = mock.MagicMock()
        newest.serial_number = 42
        entry = mock.MagicMock()
        conn = mock.MagicMock()
        mock_api.Backend.ldap2 = conn

        mismatches = [{
            'label': 'IPA RA',
            'newest': newest,
            'dn': 'uid=ipara,ou=people,o=ipaca',
            'entry': entry,
            'update_local': True,
            'update_ldap_cert': False,
            'update_desc': False,
            'path_info': ('file', '/etc/pki/ra-agent.pem'),
            'expected_desc': '2;42;CN=CA;CN=RA',
        }]

        mock_x509.write_certificate = mock.MagicMock()
        DeploymentDetector._fix_ra_subsystem_mismatches(mismatches)
        mock_x509.write_certificate.assert_called_once_with(
            newest, '/etc/pki/ra-agent.pem')


class TestUnitPrintRaSubsystemMismatches:
    """Characterization: _print_ra_subsystem_mismatches output."""

    def test_prints_all_mismatch_types(self, capsys):

        mismatches = [{
            'label': 'IPA RA', 'newest': mock.MagicMock(serial_number=42),
            'dn': 'uid=ipara,ou=people,o=ipaca',
            'update_local': True,
            'update_ldap_cert': True,
            'update_desc': True,
        }]
        DeploymentDetector._print_ra_subsystem_mismatches(mismatches)
        captured = capsys.readouterr()
        assert 'local cert is older' in captured.out
        assert 'certificate blob missing' in captured.out
        assert 'description serial mismatch' in captured.out

    def test_only_desc_mismatch(self, capsys):

        mismatches = [{
            'label': 'CA Subsystem',
            'newest': mock.MagicMock(serial_number=99),
            'dn': 'uid=pkidbuser,ou=people,o=ipaca',
            'update_local': False,
            'update_ldap_cert': False,
            'update_desc': True,
        }]
        DeploymentDetector._print_ra_subsystem_mismatches(mismatches)
        captured = capsys.readouterr()
        assert 'description serial mismatch' in captured.out
        assert 'local cert is older' not in captured.out


class TestUnitRunMethod:
    """Characterization: run() bootstrap and early exits."""

    @mock.patch(MODULE + '.is_ipa_configured', return_value=False)
    def test_not_configured_returns_2(self, _mock, capsys):
        from ipaserver.install.ipa_cert_fix import IPACertFix
        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        result = obj.run()
        assert result == 2

    @mock.patch(MODULE + '.dsinstance')
    @mock.patch(MODULE + '.realm_to_serverid', return_value='EXAMPLE-COM')
    @mock.patch(MODULE + '.api')
    @mock.patch(MODULE + '.is_ipa_configured', return_value=True)
    def test_ds_not_running_returns_1(
        self, _cfg, mock_api, mock_r2s, mock_ds, capsys,
    ):
        from ipaserver.install.ipa_cert_fix import IPACertFix
        mock_api.env.host = 'local.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'
        mock_ds.is_ds_running.return_value = False

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.force_server = None
        result = obj.run()
        assert result == 1
        captured = capsys.readouterr()
        assert 'LDAP server is not running' in captured.out

    def test_not_root_raises(self):
        """T-PRE-2: validate_options rejects non-root user."""
        import os
        from ipapython.admintool import ScriptError
        from ipaserver.install.ipa_cert_fix import IPACertFix

        if os.getegid() == 0:
            pytest.skip("test must run as non-root")

        obj = object.__new__(IPACertFix)
        obj.options = mock.MagicMock()
        obj.options.verbose = False
        obj.options.quiet = False
        obj.options.renewal_master = False
        obj.options.force_server = None
        obj.option_parser = mock.MagicMock()
        with pytest.raises(ScriptError, match="Must be root"):
            obj.validate_options()


class TestUnitGetMasterServer:
    """Characterization: get_master_server resolution paths."""

    def _make_detector(self, force_server=None, unattended=False):
        options = mock.MagicMock()
        options.force_server = force_server
        options.unattended = unattended
        return DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=options,
        )

    @mock.patch(SMOD + '._check_tcp_reachable')
    @mock.patch(SMOD + '.find_providing_servers', return_value=[])
    @mock.patch(SMOD + '.api')
    def test_force_server_returned(self, mock_api, mock_fps, mock_tcp):
        """--force-server value is used directly."""
        mock_api.env.host = 'local.example.com'
        obj = self._make_detector(force_server='master.example.com')
        result = obj.get_master_server()
        assert result == 'master.example.com'
        mock_tcp.assert_called_once_with('master.example.com')

    @mock.patch(SMOD + '._find_current_renewal_master',
                return_value='rm.example.com')
    @mock.patch(SMOD + '.find_providing_servers', return_value=[])
    @mock.patch(SMOD + '.api')
    def test_unattended_uses_renewal_master(
        self, mock_api, mock_fps, mock_frm,
    ):
        """Unattended uses renewal master from LDAP as default."""
        mock_api.env.host = 'local.example.com'
        obj = self._make_detector(unattended=True)
        result = obj.get_master_server()
        assert result == 'rm.example.com'

    @mock.patch(SMOD + '._find_current_renewal_master',
                return_value=None)
    @mock.patch(SMOD + '.find_providing_servers', return_value=[])
    @mock.patch(SMOD + '.api')
    def test_unattended_no_default_returns_none(
        self, mock_api, mock_fps, mock_frm,
    ):
        """Unattended with no renewal master and no CA servers -> None."""
        mock_api.env.host = 'local.example.com'
        obj = self._make_detector(unattended=True)
        result = obj.get_master_server()
        assert result is None

    @mock.patch(SMOD + '._find_current_renewal_master',
                return_value=None)
    @mock.patch(SMOD + '.find_providing_servers',
                return_value=['ca1.example.com'])
    @mock.patch(SMOD + '.api')
    def test_unattended_uses_first_ca_server(
        self, mock_api, mock_fps, mock_frm,
    ):
        """Unattended, no RM, but CA servers -> uses first one."""
        mock_api.env.host = 'local.example.com'
        obj = self._make_detector(unattended=True)
        result = obj.get_master_server()
        assert result == 'ca1.example.com'

    @mock.patch(SMOD + '._check_tcp_reachable')
    @mock.patch(SMOD + '.ipautil.user_input',
                return_value='chosen.example.com')
    @mock.patch(SMOD + '._find_current_renewal_master',
                return_value=None)
    @mock.patch(SMOD + '.find_providing_servers', return_value=[])
    @mock.patch(SMOD + '.api')
    def test_interactive_user_input(
        self, mock_api, mock_fps, mock_frm, mock_input, mock_tcp,
    ):
        """Interactive: user types a server FQDN."""
        mock_api.env.host = 'local.example.com'
        obj = self._make_detector()
        result = obj.get_master_server()
        assert result == 'chosen.example.com'


class TestUnitGenerateCsrFromKeySuccess:
    """Characterization: _generate_csr_from_key success path."""

    @mock.patch(SMOD + '.api')
    def test_file_based_csr_generated(self, mock_api, tmp_path):
        """Generates CSR from file-based key and expired cert SANs."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography import x509 as crypto_x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        import datetime as dt

        mock_api.env.host = 'server.example.com'
        mock_api.env.realm = 'EXAMPLE.COM'
        mock_api.env.domain = 'example.com'

        # Generate a real test key
        key = rsa.generate_private_key(65537, 2048)
        key_path = str(tmp_path / 'test.key')
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))

        # Build a minimal expired cert
        subject = crypto_x509.Name([
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, 'server'), ])
        cert = (
            crypto_x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(dt.datetime(2020, 1, 1))
            .not_valid_after(dt.datetime(2021, 1, 1))
            .add_extension(
                crypto_x509.SubjectAlternativeName([
                    crypto_x509.DNSName('server.example.com'), ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        handler = ExternalCertHandler(cm_client=mock.MagicMock())
        ctx = mock.MagicMock()
        ctx.subject_base = 'O=EXAMPLE.COM'

        with mock.patch(SMOD + '.paths') as mock_paths:
            mock_paths.HTTPD_CERT_FILE = '/cert.pem'
            mock_paths.HTTPD_KEY_FILE = key_path
            mock_paths.HTTPD_PASSWD_FILE_FMT = str(tmp_path / '{host}')
            with mock.patch(SMOD + '.ipa_certs') as mock_ic:
                mock_ic.get_default_profile.return_value = ('caIPAserviceCert')
                with mock.patch(SMOD + '.IPA_CA_RECORD', 'ipa-ca'):
                    result = handler._generate_csr_from_key(
                        IPACertType.HTTPS, cert, ctx)

        assert result is not None
        assert '-----BEGIN CERTIFICATE REQUEST-----' in result


class TestUnitFixCertreqDirectives:
    """Characterization: fix_certreq_directives."""

    @mock.patch(MODULE + '.get_csr_from_certmonger',
                return_value='BASE64CSR==')
    @mock.patch(MODULE + '.directivesetter')
    @mock.patch(MODULE + '.paths')
    def test_missing_directive_restored(
        self, mock_paths, mock_ds, mock_get_csr,
    ):
        """Missing CSR directive is restored from certmonger."""
        from ipaserver.install.ipa_cert_fix import fix_certreq_directives
        mock_paths.CA_CS_CFG_PATH = '/var/lib/pki/pki-tomcat/ca/CS.cfg'
        mock_paths.KRA_CS_CFG_PATH = '/var/lib/pki/pki-tomcat/kra/CS.cfg'
        mock_ds.get_directive.return_value = None

        cert = mock.MagicMock()
        fix_certreq_directives([('sslserver', cert)])

        mock_ds.set_directive.assert_called_once()
        args = mock_ds.set_directive.call_args[0]
        assert args[1] == 'ca.sslserver.certreq'
        assert args[2] == 'BASE64CSR=='

    @mock.patch(MODULE + '.directivesetter')
    @mock.patch(MODULE + '.paths')
    def test_existing_directive_not_touched(
        self, mock_paths, mock_ds,
    ):
        """Existing CSR directive is left alone."""
        from ipaserver.install.ipa_cert_fix import fix_certreq_directives
        mock_paths.CA_CS_CFG_PATH = '/var/lib/pki/pki-tomcat/ca/CS.cfg'
        mock_paths.KRA_CS_CFG_PATH = '/var/lib/pki/pki-tomcat/kra/CS.cfg'
        mock_ds.get_directive.return_value = 'EXISTINGCSR'

        cert = mock.MagicMock()
        fix_certreq_directives([('sslserver', cert)])

        mock_ds.set_directive.assert_not_called()


class TestUnitRunCertFix:
    """Characterization: run_cert_fix command construction."""

    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.realm_to_serverid', return_value='EXAMPLE-COM')
    @mock.patch(MODULE + '.paths')
    @mock.patch(MODULE + '.api')
    def test_builds_correct_command(
        self, mock_api, mock_paths, mock_r2s, mock_ipautil,
    ):
        """Verify pki-server cert-fix command includes certs."""
        from ipaserver.install.ipa_cert_fix import run_cert_fix

        mock_api.env.realm = 'EXAMPLE.COM'
        mock_paths.SLAPD_INSTANCE_SOCKET_TEMPLATE = (
            '/var/run/slapd-%s.socket')

        cert_dog = mock.MagicMock()
        cert_ipa = mock.MagicMock()
        cert_ipa.serial_number = 42

        run_cert_fix(
            [('sslserver', cert_dog)],
            [(IPACertType.HTTPS, cert_ipa)])

        mock_ipautil.run.assert_called_once()
        cmd = mock_ipautil.run.call_args[0][0]
        assert 'pki-server' in cmd
        assert 'cert-fix' in cmd
        assert '--cert' in cmd
        assert 'sslserver' in cmd
        assert '--extra-cert' in cmd
        assert '42' in cmd


class TestUnitCheckCaSigningCert:
    """Characterization: _check_ca_signing_cert validity check."""

    @mock.patch(SMOD + '._get_pki_nssdb')
    def test_valid_cert_returns_true(self, mock_nssdb):
        import datetime as dt

        cert = mock.MagicMock()
        cert.not_valid_after_utc = dt.datetime(
            2030, 1, 1, tzinfo=dt.timezone.utc)
        mock_nssdb.return_value.get_cert.return_value = cert

        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )
        assert obj._check_ca_signing_cert() is True

    @mock.patch(SMOD + '._get_pki_nssdb')
    def test_near_expiry_returns_false(self, mock_nssdb, capsys):
        import datetime as dt

        cert = mock.MagicMock()
        cert.not_valid_after_utc = dt.datetime(
            2026, 4, 25, tzinfo=dt.timezone.utc)
        mock_nssdb.return_value.get_cert.return_value = cert

        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )
        assert obj._check_ca_signing_cert() is False
        captured = capsys.readouterr()
        assert 'ipa-cacert-manage' in captured.out

    @mock.patch(SMOD + '._get_pki_nssdb')
    def test_unreadable_returns_false(self, mock_nssdb, capsys):
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=mock.MagicMock(),
        )
        mock_nssdb.return_value.get_cert.side_effect = RuntimeError("db error")
        assert obj._check_ca_signing_cert() is False


class TestUnitIdempotencyInterrupt:
    """T-IDEM-3 unit variant: interrupted fix leaves clean state."""

    @mock.patch(MODULE + '._kill_stuck_helpers')
    @mock.patch(MODULE + '.install_ipa_certs')
    @mock.patch(MODULE + '.replicate_dogtag_certs')
    @mock.patch(MODULE + '.run_cert_fix',
                side_effect=KeyboardInterrupt)
    @mock.patch(MODULE + '.fix_certreq_directives')
    @mock.patch(MODULE + '.ipautil')
    @mock.patch(MODULE + '.api')
    def test_keyboard_interrupt_during_cert_fix(
        self, mock_api, mock_ipautil, mock_fix_dir,
        mock_run_cf, mock_repl, mock_install, mock_ksh,
    ):
        """KeyboardInterrupt during pki-server cert-fix propagates
        but LDAP is still disconnected cleanly by run()."""
        from ipaserver.install.ipa_cert_fix import (
            IPACertFix, CertFixContext,
        )

        mock_ipautil.CalledProcessError = Exception
        mock_ipautil.run.return_value = mock.MagicMock(returncode=0)
        mock_api.env.host = 'master.example.com'

        obj = object.__new__(IPACertFix)
        obj._cm = mock.MagicMock()
        obj._cm.is_responsive.return_value = True
        obj.options = mock.MagicMock()
        obj.options.dry_run = False
        obj.options.unattended = True
        obj._scenario_made_changes = False
        obj._ca_instance = mock.MagicMock()
        obj._detector = mock.MagicMock()
        obj._detector._check_ca_signing_cert.return_value = True
        obj._detector.check_is_renewal_master.return_value = True
        obj._external_handler = mock.MagicMock()

        cert = mock.MagicMock()
        ctx = CertFixContext(
            deployment_type=DeploymentType.CA_SELF_SIGNED,
            scenario=FixScenario.RENEWAL_MASTER,
            subject_base=mock.MagicMock(),
            ca_subject_dn=mock.MagicMock(),
            dogtag_certs=[('sslserver', cert)],
            ipa_certs=[],
            external_certs=[],
            master_server=None,
        )

        with pytest.raises(KeyboardInterrupt):
            obj.run_renewal_master_fix(ctx)

        # Postcondition P5: certmonger state not corrupted
        # (run_cert_fix raised before any certmonger modification)
        obj._cm.resubmit_request.assert_not_called()
