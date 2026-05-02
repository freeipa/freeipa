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
    CertmongerClient,
)
from ipaserver.install.ipa_cert_fix_types import (
    CertIdentity,
    DOGTAG_CERTS,
)

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
