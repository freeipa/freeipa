#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Unit tests for ipa-cert-fix.

These tests use mocks and do not require an IPA deployment.  They exercise
pure logic and should run in seconds.
"""
from unittest import mock
import pytest

from ipaserver.install.ipa_cert_fix import (
    CertFixContext,
    CertRenewalFromMaster,
    CertmongerClient,
    DeploymentDetector,
    DeploymentType,
    FixScenario,
    IPACertType,
)
from ipaserver.install.ipa_cert_fix_types import (
    CertIdentity,
    DOGTAG_CERTS,
)

MODULE = 'ipaserver.install.ipa_cert_fix'
SMOD = 'ipaserver.install.ipa_cert_fix_services'


class TestCertIdentityRegistry:
    """CertIdentity dataclass and DOGTAG_CERTS registry invariants."""

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
        """Shared certs (except ca_issuing and sslserver) must have CS.cfg
        directives so the cert blob can be updated in-place."""
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
    """CertmongerClient adapter delegation and retry logic."""

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


class TestUnitDeploymentDetection:
    """detect_deployment_type with all 4 return values."""

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
    def test_ca_self_signed(self, mock_ca, mock_nssdb, mock_api, mock_fps):
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
    def test_ca_less_external(self, mock_ca, mock_api, mock_fps, mock_elc):
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

    @mock.patch(SMOD + '.api')
    @mock.patch(SMOD + '._get_pki_nssdb')
    @mock.patch(SMOD + '.cainstance')
    def test_nssdb_unreadable_raises(self, mock_ca, mock_nssdb, mock_api):
        """CA installed but NSSDB unreadable -> RuntimeError."""
        mock_ca.is_ca_installed_locally.return_value = True
        mock_nssdb.return_value.get_cert.side_effect = RuntimeError("db error")

        obj = self._make_detector()
        with pytest.raises(RuntimeError, match="Cannot read caSigningCert"):
            obj.detect_deployment_type()


class TestUnitScenarioRouting:
    """Scenario routing for each deployment type."""

    def _make_detector(self, is_rm, master, force_rm=False):
        options = mock.MagicMock()
        options.renewal_master = force_rm
        options.force_server = None
        options.unattended = False
        obj = DeploymentDetector(
            cm_client=mock.MagicMock(),
            ca_instance=mock.MagicMock(),
            options=options,
        )
        obj.check_is_renewal_master = mock.MagicMock(return_value=is_rm)
        obj.get_master_server = mock.MagicMock(return_value=master)
        return obj

    @pytest.mark.parametrize("dt,is_rm,master,expected_scenario", [
        (DeploymentType.CA_SELF_SIGNED,
         True, None, FixScenario.RENEWAL_MASTER),
        (DeploymentType.CA_SELF_SIGNED,
         False, 'master.example.com', FixScenario.CA_FULL_WITH_MASTER),
        (DeploymentType.CA_SELF_SIGNED,
         False, None, FixScenario.CA_FULL_PROMOTE),
        (DeploymentType.CA_EXTERNALLY_SIGNED,
         True, None, FixScenario.RENEWAL_MASTER),
        (DeploymentType.CA_EXTERNALLY_SIGNED,
         False, 'master.example.com', FixScenario.CA_FULL_WITH_MASTER),
        (DeploymentType.CA_LESS,
         False, 'master.example.com', FixScenario.CA_LESS_WITH_MASTER),
        (DeploymentType.CA_LESS_EXTERNAL,
         False, None, FixScenario.EXTERNAL_CERTS),
    ])
    def test_scenario_matrix(self, dt, is_rm, master, expected_scenario):
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
            is_rm=False, master='m.example.com', force_rm=True,
        )
        scenario, srv = obj.determine_scenario(
            DeploymentType.CA_SELF_SIGNED)
        assert scenario == FixScenario.RENEWAL_MASTER
        assert srv is None


class TestUnitCertClassification:
    """Cert classification splits external from IPA."""

    @mock.patch(SMOD + '.cainstance')
    @mock.patch(SMOD + '.expired_dogtag_certs')
    @mock.patch(SMOD + '.expired_ipa_certs')
    def test_external_certs_split(
        self, mock_exp_ipa, mock_exp_dog, mock_ca,
    ):
        """Verify _classify_certs moves non_renewed to external."""
        import datetime as dt
        now = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        mock_ca.is_ca_installed_locally.return_value = True

        cert_mock = mock.MagicMock()
        mock_exp_dog.return_value = [('ca_audit', cert_mock)]
        mock_exp_ipa.return_value = (
            [(IPACertType.IPARA, cert_mock)],
            [(IPACertType.HTTPS, cert_mock)],  # non_renewed -> external
        )

        dogtag, ipa, external = DeploymentDetector._classify_certs(now)

        assert len(dogtag) == 1
        assert len(ipa) == 1
        assert len(external) == 1
        assert external[0][0] == IPACertType.HTTPS

    @mock.patch(SMOD + '.cainstance')
    @mock.patch(SMOD + '.expired_ipa_certs')
    def test_caless_skips_dogtag(self, mock_exp_ipa, mock_ca):
        """On CA-less, dogtag certs list is empty."""
        import datetime as dt
        now = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        mock_ca.is_ca_installed_locally.return_value = False

        cert_mock = mock.MagicMock()
        mock_exp_ipa.return_value = (
            [(IPACertType.HTTPS, cert_mock)],
            [],
        )

        dogtag, ipa, external = DeploymentDetector._classify_certs(now)

        assert dogtag == []
        assert len(ipa) == 1


def _make_ctx(**overrides):
    """Build a minimal CertFixContext with optional field overrides."""
    fields = dict(
        deployment_type=DeploymentType.CA_SELF_SIGNED,
        scenario=FixScenario.CA_FULL_WITH_MASTER,
        subject_base='O=TEST',
        ca_subject_dn='CN=CA',
        dogtag_certs=[],
        ipa_certs=[],
        external_certs=[],
        master_server='m.example.com',
        serverid='TEST',
        ds_dbdir='/etc/dirsrv/slapd-TEST',
        ds_nickname='Server-Cert',
    )
    fields.update(overrides)
    return CertFixContext(**fields)


class TestUnitBuildTrackingList:
    """_build_tracking_list filtering logic."""

    def test_skips_subsystem_and_ra(self):
        """subsystem and RA certs are skipped (fetched separately from
        master's LDAP)."""
        cert = mock.MagicMock()
        ctx = _make_ctx()

        dogtag = [('subsystem', cert), ('sslserver', cert)]
        ipa = [(IPACertType.IPARA, cert), (IPACertType.HTTPS, cert)]

        obj = CertRenewalFromMaster(mock.MagicMock(), 'm.example.com')
        tracking = obj._build_tracking_list(dogtag, ipa, ctx)

        descs = [d for d, _c, _cr, _l in tracking]
        desc_ids = [getattr(d, 'id', d) for d in descs]
        assert 'subsystem' not in desc_ids
        assert IPACertType.IPARA not in descs
        assert 'sslserver' in desc_ids
        assert IPACertType.HTTPS in descs

    def test_all_ipa_cert_types_mapped(self):
        """HTTPS, LDAPS, KDC all produce tracking entries."""
        cert = mock.MagicMock()
        ctx = _make_ctx()

        ipa = [
            (IPACertType.HTTPS, cert),
            (IPACertType.LDAPS, cert),
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
    """_make_cert_loader factory."""

    @mock.patch(SMOD + '.NSSDatabase')
    def test_nssdb_loader(self, mock_nss):
        """NSSDB loader calls db.get_cert(nickname)."""
        db = mock.MagicMock()
        mock_nss.return_value = db

        loader = CertRenewalFromMaster._make_cert_loader(
            'NSSDB', '/some/db', 'MyCert')
        loader()
        db.get_cert.assert_called_once_with('MyCert')

    @mock.patch(SMOD + '.x509')
    def test_file_loader(self, mock_x509):
        """FILE loader calls load_certificate_from_file."""
        loader = CertRenewalFromMaster._make_cert_loader(
            'FILE', '/some/cert.pem')
        loader()
        mock_x509.load_certificate_from_file.assert_called_once_with(
            '/some/cert.pem')


class TestUnitSetIpaCaHelperStripping:
    """_set_helper / set_ca_override strips leftover -J."""

    @mock.patch(SMOD + '.certmonger')
    def test_strips_stale_j_flag(self, mock_cm):
        """If old helper already has -J from a crashed run, the stale
        -J is stripped before appending the new one."""
        stale = '/usr/libexec/ipa-submit -J https://old.example.com/ipa/json'
        client = CertmongerClient()
        client.get_ca_helper = mock.MagicMock(return_value=stale)

        result = client.set_ca_override('IPA', 'new.example.com')

        assert result == '/usr/libexec/ipa-submit'
        new_helper = mock_cm.modify_ca_helper.call_args[0][1]
        assert new_helper.count('-J') == 1
        assert 'new.example.com' in new_helper


class TestUnitPartialRenewalFailure:
    """Partial failure in CertRenewalFromMaster.renew."""

    def test_failed_cert_not_in_renewed_ids(self):
        """Failed certs excluded from renewed_ids."""
        obj = CertRenewalFromMaster(mock.MagicMock(), 'master.example.com')

        obj._build_tracking_list = mock.MagicMock(return_value=[
            ('sslserver', mock.MagicMock(), {}, mock.MagicMock()),
            ('httpd', mock.MagicMock(), {}, mock.MagicMock()),
        ])
        obj._resolve_tracking_requests = mock.MagicMock(return_value=[
            ('sslserver', mock.MagicMock(), 'req1', 'dogtag', None),
            ('httpd', mock.MagicMock(), 'req2', 'IPA', None),
        ])
        obj._set_helper = mock.MagicMock(return_value='old')
        obj._restore_helper = mock.MagicMock()
        obj._restore = mock.MagicMock()

        obj._resubmit = mock.MagicMock(
            side_effect=[None, RuntimeError("timeout")])

        ctx = mock.MagicMock()
        ctx.dogtag_certs = []
        ctx.ipa_certs = []
        result = obj.renew([], [], ctx)

        assert 'req1' in result
        assert 'req2' not in result


class TestUnitSetHelperTimeout:
    """D-Bus timeout in _set_helper."""

    def test_dbus_timeout_raises(self):
        """_set_helper raises when set_ca_override fails."""
        import dbus
        cm = mock.MagicMock()
        cm.set_ca_override.side_effect = \
            dbus.exceptions.DBusException("timeout")

        obj = CertRenewalFromMaster(cm, 'master.example.com')
        with pytest.raises(dbus.exceptions.DBusException):
            obj._set_helper()
