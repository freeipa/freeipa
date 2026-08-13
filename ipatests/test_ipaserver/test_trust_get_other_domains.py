# Copyright (C) 2026  FreeIPA Contributors - see LICENSE file

from unittest import mock

import pytest

import ipaserver.dcerpc  # noqa: F401 -- ensures ipaserver.dcerpc is loaded
import ipaserver.plugins.trust as trust_plugin_module
from ipalib import errors
from ipapython.dn import DN
from ipaserver.plugins.trust import trust as trust_object
from ipaserver.plugins.trust import trust_mod as trust_mod_class


class FakeEntry(dict):
    def __init__(self, dn, attrs):
        super(FakeEntry, self).__init__(attrs)
        self.dn = dn

    @property
    def single_value(self):
        return {k: v[0] for k, v in self.items() if v}


class TestGetOtherTrustedDomains:
    def test_excludes_own_trust_root_and_subdomains(self):
        own_dn = DN('cn=a.test,cn=ad,cn=trusts,dc=ipa,dc=test')
        other_root_dn = DN('cn=d.test,cn=ad,cn=trusts,dc=ipa,dc=test')
        own_child_dn = DN(
            'cn=c.b.a.test,cn=a.test,cn=ad,cn=trusts,dc=ipa,dc=test')

        entries = [
            FakeEntry(own_dn, {
                'cn': ['a.test'],
                'ipantadditionalsuffixes': [],
                'ipanttrusttlnexclusions': [],
            }),
            FakeEntry(own_child_dn, {
                'cn': ['c.b.a.test'],
            }),
            FakeEntry(other_root_dn, {
                'cn': ['d.test'],
                'ipantadditionalsuffixes': ['deep.c.b.a.test'],
                'ipanttrusttlnexclusions': ['old.test'],
            }),
        ]

        ldap = mock.MagicMock()
        ldap.find_entries.return_value = (entries, False)

        mock_api = mock.MagicMock()
        mock_api.env.container_trusts = 'cn=ad,cn=trusts'
        mock_api.env.basedn = DN('dc=ipa,dc=test')
        obj = trust_object(mock_api)

        result = obj.get_other_trusted_domains(ldap, own_dn)

        assert result == [
            {'cn': 'd.test', 'suffixes': ['deep.c.b.a.test'],
             'exclusions': ['old.test']},
        ]

    def test_does_not_match_unrelated_domain_sharing_a_substring(self):
        # "nota.test" shares the substring "a.test" with own_dn's RDN
        # value, but is a completely unrelated root trust -- DN
        # comparison must be RDN-component-aware, not a plain string
        # suffix check.
        own_dn = DN('cn=a.test,cn=ad,cn=trusts,dc=ipa,dc=test')
        unrelated_dn = DN('cn=nota.test,cn=ad,cn=trusts,dc=ipa,dc=test')

        entries = [
            FakeEntry(unrelated_dn, {
                'cn': ['nota.test'],
                'ipantadditionalsuffixes': [],
                'ipanttrusttlnexclusions': [],
            }),
        ]

        ldap = mock.MagicMock()
        ldap.find_entries.return_value = (entries, False)

        mock_api = mock.MagicMock()
        mock_api.env.container_trusts = 'cn=ad,cn=trusts'
        mock_api.env.basedn = DN('dc=ipa,dc=test')
        obj = trust_object(mock_api)

        result = obj.get_other_trusted_domains(ldap, own_dn)

        assert result == [
            {'cn': 'nota.test', 'suffixes': [], 'exclusions': []},
        ]


class TestTrustModCollisionValidation:
    @pytest.fixture(autouse=True)
    def enable_bindings(self, monkeypatch):
        # _bindings_installed/ipaserver are only bound at trust.py import
        # time when api.env.in_server is True (a real server process).
        # Under the unit-test bootstrap used here, in_server is False, so
        # trust_mod.pre_callback's dcerpc calls need these bound manually.
        monkeypatch.setattr(
            trust_plugin_module, '_bindings_installed', True, raising=False)
        monkeypatch.setattr(
            trust_plugin_module, 'ipaserver', ipaserver, raising=False)

    def _make_trust_mod(self, other_trusts, current_attrs=None):
        mock_api = mock.MagicMock()
        mock_obj = mock.MagicMock()
        mock_obj.validate_sid_blocklists = mock.MagicMock()
        mock_obj.get_other_trusted_domains = mock.MagicMock(
            return_value=other_trusts)
        mock_api.Object.__getitem__.return_value = mock_obj

        cmd = trust_mod_class(mock_api)

        ldap = mock.MagicMock()
        ldap.get_entry.return_value = current_attrs or {}
        return cmd, ldap

    def test_colliding_suffix_is_rejected(self):
        dn = DN('cn=d.test,cn=ad,cn=trusts,dc=ipa,dc=test')
        other_trusts = [
            {'cn': 'a.test', 'suffixes': [], 'exclusions': []},
            {'cn': 'c.b.a.test', 'suffixes': [], 'exclusions': []},
        ]
        cmd, ldap = self._make_trust_mod(other_trusts)
        e_attrs = {'ipantadditionalsuffixes': ['deep.c.b.a.test']}

        with pytest.raises(errors.TrustTopologyConflictError):
            cmd.pre_callback(ldap, dn, e_attrs, [])

    def test_excluded_suffix_is_accepted(self):
        dn = DN('cn=d.test,cn=ad,cn=trusts,dc=ipa,dc=test')
        other_trusts = [
            {'cn': 'c.b.a.test', 'suffixes': [],
             'exclusions': ['deep.c.b.a.test']},
        ]
        cmd, ldap = self._make_trust_mod(other_trusts)
        e_attrs = {'ipantadditionalsuffixes': ['deep.c.b.a.test']}

        result_dn = cmd.pre_callback(ldap, dn, e_attrs, [])

        assert result_dn is dn
        assert 'ipanttrustforesttrustinfo' in e_attrs

    def test_resending_same_suffixes_skips_blob_rebuild(self):
        dn = DN('cn=d.test,cn=ad,cn=trusts,dc=ipa,dc=test')
        other_trusts = [
            {'cn': 'unrelated-forest.test', 'suffixes': [],
             'exclusions': []},
        ]
        current_attrs = {'ipantadditionalsuffixes': ['Deep.C.B.A.Test']}
        cmd, ldap = self._make_trust_mod(other_trusts, current_attrs)
        # Same value already stored, just different case -- an idempotent
        # automation re-run resending its desired state.
        e_attrs = {'ipantadditionalsuffixes': ['deep.c.b.a.test']}

        result_dn = cmd.pre_callback(ldap, dn, e_attrs, [])

        assert result_dn is dn
        assert 'ipanttrustforesttrustinfo' not in e_attrs

    def test_actual_suffix_change_still_rebuilds_blob(self):
        dn = DN('cn=d.test,cn=ad,cn=trusts,dc=ipa,dc=test')
        other_trusts = [
            {'cn': 'unrelated-forest.test', 'suffixes': [],
             'exclusions': []},
        ]
        current_attrs = {'ipantadditionalsuffixes': ['old.suffix.test']}
        cmd, ldap = self._make_trust_mod(other_trusts, current_attrs)
        e_attrs = {'ipantadditionalsuffixes': ['new.suffix.test']}

        result_dn = cmd.pre_callback(ldap, dn, e_attrs, [])

        assert result_dn is dn
        assert 'ipanttrustforesttrustinfo' in e_attrs
