#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Tests for krbPrincipalMatch matching rule plugin"""
from __future__ import absolute_import

import textwrap

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


def service_entry_ldif(princ, realm, suffix):
    dn = 'krbprincipalname={}@{},cn=services,cn=accounts,{}'.format(
        princ, realm, suffix)
    ldif = textwrap.dedent("""\
        dn: {dn}
        objectClass: top
        objectClass: krbPrincipal
        objectClass: krbPrincipalAux
        objectClass: krbTicketPolicyAux
        objectClass: ipaKrbPrincipal
        objectClass: ipaService
        objectClass: pkiUser
        objectClass: ipaObject
        krbPrincipalName: {princ}@{realm}
        krbCanonicalName: {princ}@{realm}
        ipakrbprincipalalias: {princ}@{realm}
        ipaUniqueID: autogenerate
    """).format(dn=dn, princ=princ, realm=realm)
    return dn, ldif


class TestKrbPrincipalMatch(IntegrationTest):
    """Tests for the krbPrincipalMatch matching rule plugin.

    Verifies that the matching rule is loaded, that extensible match
    LDAP searches work, and that the uniqueness plugin correctly
    rejects duplicate Kerberos principals using krbPrincipalMatch.
    """

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_plugin_loaded(self):
        """Verify the krbPrincipalMatch plugin is loaded"""
        result = tasks.ldapsearch_dm(
            self.master,
            'cn=IPA Kerberos Principal Match,cn=plugins,cn=config',
            ['nsslapd-pluginEnabled'],
            scope='base',
        )
        assert 'nsslapd-pluginEnabled: on' in result.stdout_text

    def test_matching_rule_in_schema(self):
        """Verify that krbPrincipalMatch appears in the root DSE schema"""
        result = tasks.ldapsearch_dm(
            self.master,
            'cn=schema',
            ['(objectclass=subschema)',
             'matchingRules'],
            scope='base',
        )
        assert 'krbPrincipalMatch' in result.stdout_text

    def test_extensible_match_search(self):
        """Test that extensible match filter with krbPrincipalMatch works"""
        realm = self.master.domain.realm
        suffix = self.master.domain.basedn

        # admin principal should be found
        result = tasks.ldapsearch_dm(
            self.master,
            str(suffix),
            ['(krbPrincipalName:krbPrincipalMatch:=admin@{})'.format(realm),
             'krbPrincipalName'],
        )
        assert 'krbPrincipalName: admin@{}'.format(realm) in result.stdout_text

    def test_extensible_match_case_insensitive(self):
        """Test that krbPrincipalMatch is case-insensitive"""
        realm = self.master.domain.realm
        suffix = self.master.domain.basedn

        result = tasks.ldapsearch_dm(
            self.master,
            str(suffix),
            ['(krbPrincipalName:krbPrincipalMatch:=ADMIN@{})'.format(realm),
             'krbPrincipalName'],
        )
        assert 'krbPrincipalName: admin@{}'.format(realm) in result.stdout_text

    def test_duplicate_principal_rejected(self):
        """Adding an entry with an already-existing principal is rejected"""
        realm = self.master.domain.realm
        suffix = self.master.domain.basedn

        svc = 'testmr1/{}'.format(self.master.hostname)
        svc_dn, ldif = service_entry_ldif(svc, realm, suffix)
        tasks.ldapadd_dm(self.master, ldif)

        try:
            # try to add a second entry with the same principal value
            ldif2 = textwrap.dedent("""\
                dn: cn=duplicate,cn=services,cn=accounts,{suffix}
                objectClass: top
                objectClass: krbPrincipalAux
                objectClass: krbTicketPolicyAux
                krbPrincipalName: {svc}@{realm}
            """).format(svc=svc, realm=realm, suffix=suffix)

            result = tasks.ldapadd_dm(self.master, ldif2, raiseonerr=False)
            assert result.returncode != 0
            assert 'Constraint Violation' in result.stderr_text \
                or 'already exists' in result.stderr_text.lower() \
                or result.returncode == 19
        finally:
            tasks.ldapdelete_dm(self.master, svc_dn, raiseonerr=False)

    def test_duplicate_principal_without_realm_rejected(self):
        """Adding an entry with a principal missing the realm is rejected
        when the same principal with the default realm already exists.
        """
        realm = self.master.domain.realm
        suffix = self.master.domain.basedn

        svc = 'testmr2/{}'.format(self.master.hostname)
        svc_dn, ldif = service_entry_ldif(svc, realm, suffix)
        tasks.ldapadd_dm(self.master, ldif)

        try:
            # add entry with principal WITHOUT realm — should be caught
            # by krbPrincipalMatch which normalizes to default realm
            ldif2 = textwrap.dedent("""\
                dn: cn=norealm,cn=services,cn=accounts,{suffix}
                objectClass: top
                objectClass: krbPrincipalAux
                objectClass: krbTicketPolicyAux
                krbPrincipalName: {svc}
            """).format(svc=svc, suffix=suffix)

            result = tasks.ldapadd_dm(self.master, ldif2, raiseonerr=False)
            assert result.returncode != 0
        finally:
            tasks.ldapdelete_dm(self.master, svc_dn, raiseonerr=False)

    def test_different_principals_allowed(self):
        """Adding entries with distinct principals succeeds"""
        realm = self.master.domain.realm
        suffix = self.master.domain.basedn

        svc1 = 'testmr3a/{}'.format(self.master.hostname)
        svc2 = 'testmr3b/{}'.format(self.master.hostname)
        svc1_dn, ldif1 = service_entry_ldif(svc1, realm, suffix)
        svc2_dn, ldif2 = service_entry_ldif(svc2, realm, suffix)

        try:
            tasks.ldapadd_dm(self.master, ldif1)
            tasks.ldapadd_dm(self.master, ldif2)
        finally:
            tasks.ldapdelete_dm(self.master, svc2_dn, raiseonerr=False)
            tasks.ldapdelete_dm(self.master, svc1_dn, raiseonerr=False)

    def test_different_realm_allowed(self):
        """Principals with a different realm are distinct"""
        realm = self.master.domain.realm
        suffix = self.master.domain.basedn

        svc = 'testmr4/{}'.format(self.master.hostname)
        svc_dn, ldif = service_entry_ldif(svc, realm, suffix)
        tasks.ldapadd_dm(self.master, ldif)

        other_dn = ('krbprincipalname={svc}@OTHER.REALM,'
                    'cn=services,cn=accounts,{suffix}').format(
                        svc=svc, suffix=suffix)
        try:
            ldif2 = textwrap.dedent("""\
                dn: {dn}
                objectClass: top
                objectClass: krbPrincipal
                objectClass: krbPrincipalAux
                objectClass: krbTicketPolicyAux
                krbPrincipalName: {svc}@OTHER.REALM
            """).format(dn=other_dn, svc=svc)

            result = tasks.ldapadd_dm(self.master, ldif2)
            assert result.returncode == 0
            tasks.ldapdelete_dm(
                self.master, other_dn, raiseonerr=False,
            )
        finally:
            tasks.ldapdelete_dm(self.master, svc_dn, raiseonerr=False)

    def test_ipa_service_add_duplicate_rejected(self):
        """ipa service-add rejects a service whose principal already exists"""
        tasks.kinit_admin(self.master)

        svc1 = 'testsvc1/{}'.format(self.master.hostname)
        svc2 = 'testsvc1/{}'.format(self.master.hostname)

        self.master.run_command(['ipa', 'service-add', '--force', svc1])
        try:
            result = self.master.run_command(
                ['ipa', 'service-add', '--force', svc2], raiseonerr=False,
            )
            assert result.returncode != 0
        finally:
            self.master.run_command(
                ['ipa', 'service-del', svc1], raiseonerr=False,
            )
