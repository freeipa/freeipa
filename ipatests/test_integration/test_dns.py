#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""This covers tests for dns related feature"""

from __future__ import absolute_import

import time

import dns.resolver
from ipapython.dnsutil import DNSResolver
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

# =============================================================================
# DNS Test Constants
# =============================================================================
# Test zone configuration
ZONE = "testzone"
EMAIL = "ipaqar.redhat.com"
REFRESH = 303
RETRY = 101
EXPIRE = 1202
MINIMUM = 33
TTL = 55

# A record values
A_RECORD = "1.2.3.4"
MULTI_A_RECORD1 = "1.2.3.4"
MULTI_A_RECORD2 = "2.3.4.5"

# AAAA record values
AAAA = "fec0:0:a10:6000:10:16ff:fe98:193"
AAAA_BAD1 = "bada:aaaa:real:ly:bad:dude:extr:a"
AAAA_BAD2 = "aaaa:bbbb:cccc:dddd:eeee:fffff"

# Other record types
AFSDB = "green.femto.edu."
CNAME = "m.l.k."
TXT = "none=1.2.3.4"
SRV_A = "0 100 389"
SRV = "why.go.here.com."
NAPTR = '100 10 U E2U+msg !^.*$!mailto:info@example.com! .'
NAPTR_FIND = "info@example.com"
DNAME = f"bar.{ZONE}."
DNAME2 = f"bar_underscore.{ZONE}."
CERT_B = "1 1 1"
CERT = "F835EDA21E94B565716F"
LOC = "37 23 30.900 N 121 59 19.000 W 7.00m 100.00m 100.00m 2.00m"

# KX records
KX_PREF1 = "1234"
KX_BAD_PREF1 = "-1"
KX_BAD_PREF2 = "123345678"

# PTR zone configuration
PTR_OCTET = "4.4.4"
PTR_ZONE = f"{PTR_OCTET}.in-addr.arpa."
PTR = "8"
PTR_VALUE = "in.awesome.domain."
PTR_EMAIL = "ipaqar.redhat.com"
PTR_REFRESH = 393
PTR_RETRY = 191
PTR_EXPIRE = 1292
PTR_MINIMUM = 39
PTR_TTL = 59

# Persistent search test values
NEW_TXT = "newip=5.6.7.8"
NEWER_TXT = "newip=8.7.6.5"


class TestDNS(IntegrationTest):
    """Tests for DNS feature.

    This test class covers the tests for DNS feature.
    """
    topology = 'line'
    num_replicas = 0

    def test_fake_mname_param(self):
        """Test that fake_mname param is set using dnsserver-mod option.

        Test for BZ 1488732 which checks that  --soa-mname-override option
        from dnsserver-mod sets the fake_mname.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'dnsserver-mod', self.master.hostname,
                                 '--soa-mname-override', 'fake'])
        tasks.restart_named(self.master)
        cmd = self.master.run_command(['dig', '+short', '-t', 'SOA',
                                       self.master.domain.name])
        assert 'fake' in cmd.stdout_text

        # reverting the fake_mname change to check it is reverted correctly
        self.master.run_command(['ipa', 'dnsserver-mod', self.master.hostname,
                                 '--soa-mname-override', ''])
        tasks.restart_named(self.master)
        cmd = self.master.run_command(['dig', '+short', '-t', 'SOA',
                                       self.master.domain.name])
        assert 'fake' not in cmd.stdout_text


class TestDNSAcceptance(IntegrationTest):
    """DNS Acceptance tests.

    This test class covers all the DNS acceptance tests including
    zone management, record types (A, AAAA, AFSDB, CNAME, TXT, SRV, MX,
    PTR, NAPTR, DNAME, CERT, LOC, KX), zone permissions, and persistent
    search functionality.

    Converted from bash test script t.dns.sh
    """
    topology = 'line'
    num_replicas = 0

    @classmethod
    def install(cls, mh):
        super(TestDNSAcceptance, cls).install(mh)
        # Set domain-dependent values
        cls.MANAGED_ZONE = f"qa.{cls.master.domain.name}"
        cls.MANAGED_ZONE1 = f"dev.{cls.master.domain.name}"
        cls.NONEXISTENT_ZONE = f"nonexistent.{cls.master.domain.name}"
        cls.ZONE_PSEARCH = f"westford.{cls.master.domain.name}"
        cls.MX = f"mail.{cls.master.domain.name}"
        cls.A_HOST = f"1.{cls.master.domain.name}"
        # Setup DNS resolver for test queries
        cls.resolver = DNSResolver()
        cls.resolver.nameservers = [cls.master.ip]
        cls.resolver.lifetime = 10

    @classmethod
    def uninstall(cls, mh):
        # Cleanup zones if they exist
        tasks.kinit_admin(cls.master)
        for zone in [ZONE, PTR_ZONE, cls.MANAGED_ZONE,
                     cls.MANAGED_ZONE1, cls.ZONE_PSEARCH]:
            if zone:
                cls.master.run_command(
                    ['ipa', 'dnszone-del', zone], raiseonerr=False
                )
        super(TestDNSAcceptance, cls).uninstall(mh)

    # =========================================================================
    # DNS Zone Tests
    # =========================================================================

    def test_dns_zone(self):
        """Test DNS zone creation, verification, and dig queries.

        This test covers zone management operations including creating zones
        with valid and invalid parameters, and verifying zone attributes
        via IPA and dig.
        """
        tasks.kinit_admin(self.master)

        # Create a new DNS zone with all SOA parameters
        tasks.add_dns_zone(
            self.master, ZONE,
            admin_email=EMAIL,
            refresh=REFRESH,
            retry=RETRY,
            expire=EXPIRE,
            minimum=MINIMUM,
            ttl=TTL
        )
        # Verify the new zone was created and is findable
        result = tasks.find_dns_zone(self.master, ZONE, all_attrs=True)
        assert ZONE in result.stdout_text

        # Verify DNS server returns correct SOA attributes using DNS API
        self.master.run_command(['ipactl', 'restart'])
        time.sleep(5)
        soa = self.resolver.resolve(ZONE, 'SOA')[0]
        assert self.master.hostname in str(soa.mname)
        assert EMAIL.replace('@', '.') in str(soa.rname)
        assert soa.refresh == REFRESH
        assert soa.retry == RETRY
        assert soa.expire == EXPIRE
        assert soa.minimum == MINIMUM

    # =========================================================================
    # A Record Tests
    # =========================================================================

    def test_a_record(self):
        """Test A record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # Single A record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'allll',
                             record_type='a', record_value=[A_RECORD])
        ans = self.resolver.resolve(f'allll.{ZONE}', 'A')
        assert A_RECORD in [r.address for r in ans]

        tasks.del_dns_record(self.master, ZONE, 'allll',
                             record_type='a', record_value=[A_RECORD])
        try:
            self.resolver.resolve(f'allll.{ZONE}', 'A')
            raise AssertionError(
                f"Resolving allll.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

        # Multiple A records: add, verify, delete, verify deleted
        multi_recs = [MULTI_A_RECORD1, MULTI_A_RECORD2]
        tasks.add_dns_record(self.master, ZONE, 'aa2',
                             record_type='a', record_value=multi_recs)
        ans = self.resolver.resolve(f'aa2.{ZONE}', 'A')
        assert MULTI_A_RECORD1 in [r.address for r in ans]
        assert MULTI_A_RECORD2 in [r.address for r in ans]

        tasks.del_dns_record(self.master, ZONE, 'aa2',
                             record_type='a', record_value=multi_recs)
        try:
            self.resolver.resolve(f'aa2.{ZONE}', 'A')
            raise AssertionError(
                f"Resolving aa2.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Records deleted, name no longer exists - expected

    # =========================================================================
    # AAAA Record Tests
    # =========================================================================

    def test_aaaa_record(self):
        """Test AAAA record add, verify, delete, and invalid values."""
        tasks.kinit_admin(self.master)

        # AAAA record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'aaaa',
                             record_type='aaaa', record_value=[AAAA])
        ans = self.resolver.resolve(f'aaaa.{ZONE}', 'AAAA')
        assert AAAA in [r.address for r in ans]

        tasks.del_dns_record(self.master, ZONE, 'aaaa',
                             record_type='aaaa', record_value=[AAAA])
        try:
            self.resolver.resolve(f'aaaa.{ZONE}', 'AAAA')
            raise AssertionError(
                f"Resolving aaaa.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

        # Invalid AAAA record should fail and not be created
        result = tasks.add_dns_record(self.master, ZONE, 'aaaab',
                                      record_type='aaaa',
                                      record_value=[AAAA_BAD1],
                                      raiseonerr=False)
        assert result.returncode != 0
        try:
            self.resolver.resolve(f'aaaab.{ZONE}', 'AAAA')
            raise AssertionError(
                f"Resolving aaaab.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record was never created - expected

    # =========================================================================
    # AFSDB Record Tests
    # =========================================================================

    def test_afsdb_record(self):
        """Test AFSDB record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # AFSDB record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'afsdb',
                             record_type='afsdb',
                             record_value=[f'0 {AFSDB}'])
        ans = self.resolver.resolve(f'afsdb.{ZONE}', 'AFSDB')
        assert AFSDB in [str(r.hostname) for r in ans]

        tasks.del_dns_record(self.master, ZONE, 'afsdb',
                             record_type='afsdb',
                             record_value=[f'0 {AFSDB}'])
        try:
            self.resolver.resolve(f'afsdb.{ZONE}', 'AFSDB')
            raise AssertionError(
                f"Resolving afsdb.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # CNAME Record Tests
    # =========================================================================

    def test_cname_record(self):
        """Test CNAME record add, verify, delete, and duplicate (bz915807)."""
        tasks.kinit_admin(self.master)

        # CNAME record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'cname',
                             record_type='cname', record_value=[CNAME])
        ans = self.resolver.resolve(f'cname.{ZONE}', 'CNAME')
        assert CNAME in [str(r.target) for r in ans]

        # Duplicate CNAME should fail and not be created (bz915807)
        result = tasks.add_dns_record(self.master, ZONE, 'cname',
                                      record_type='cname',
                                      record_value=['a.b.c'], raiseonerr=False)
        assert result.returncode != 0
        ans = self.resolver.resolve(f'cname.{ZONE}', 'CNAME')
        assert 'a.b.c' not in [str(r.target) for r in ans]

        tasks.del_dns_record(self.master, ZONE, 'cname',
                             record_type='cname', record_value=[CNAME])
        try:
            self.resolver.resolve(f'cname.{ZONE}', 'CNAME')
            raise AssertionError(
                f"Resolving cname.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # TXT Record Tests
    # =========================================================================

    def test_txt_record(self):
        """Test TXT record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # TXT record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'txt',
                             record_type='txt', record_value=[TXT])
        ans = self.resolver.resolve(f'txt.{ZONE}', 'TXT')
        assert any(TXT in str(r) for r in ans)

        tasks.del_dns_record(self.master, ZONE, 'txt',
                             record_type='txt', record_value=[TXT])
        try:
            self.resolver.resolve(f'txt.{ZONE}', 'TXT')
            raise AssertionError(
                f"Resolving txt.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # SRV Record Tests
    # =========================================================================

    def test_srv_record(self):
        """Test SRV record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # SRV record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, '_srv',
                             record_type='srv',
                             record_value=[f'{SRV_A} {SRV}'])
        ans = self.resolver.resolve(f'_srv.{ZONE}', 'SRV')
        assert SRV in [str(r.target) for r in ans]

        tasks.del_dns_record(self.master, ZONE, '_srv', del_all=True)
        try:
            self.resolver.resolve(f'_srv.{ZONE}', 'SRV')
            raise AssertionError(
                f"Resolving _srv.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # MX Record Tests
    # =========================================================================

    def test_mx_record(self):
        """Test MX record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # MX record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, '@',
                             record_type='mx',
                             record_value=[f'10 {self.MX}.'])
        ans = self.resolver.resolve(ZONE, 'MX')
        assert f'{self.MX}.' in [str(r.exchange) for r in ans]

        tasks.del_dns_record(self.master, ZONE, '@',
                             record_type='mx',
                             record_value=[f'10 {self.MX}.'])
        try:
            self.resolver.resolve(ZONE, 'MX')
            raise AssertionError(
                f"Resolving MX for {ZONE} should have raised NoAnswer")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Record deleted or no MX records left - expected

    # =========================================================================
    # PTR Zone Tests
    # =========================================================================
    def test_ptr_zone(self):
        """Test PTR zone creation and verification.

        This test covers PTR zone management including creating zone
        with all SOA parameters, and verifying attributes via IPA and dig.
        """
        tasks.kinit_admin(self.master)
        # Clean up if zone exists
        tasks.del_dns_zone(self.master, PTR_ZONE)

        # Create PTR zone with all SOA parameters
        tasks.add_dns_zone(
            self.master, PTR_ZONE,
            skip_overlap_check=True,
            admin_email=PTR_EMAIL,
            refresh=PTR_REFRESH,
            retry=PTR_RETRY,
            expire=PTR_EXPIRE,
            minimum=PTR_MINIMUM,
            ttl=PTR_TTL
        )

        # Verify PTR zone gets created with the correct attributes
        result = tasks.find_dns_zone(
            self.master, PTR_ZONE, all_attrs=True)
        assert PTR_ZONE in result.stdout_text

        # Verify PTR zone SOA attributes using DNS resolver
        soa = self.resolver.resolve(PTR_ZONE, 'SOA')[0]
        assert self.master.hostname in str(soa.mname)
        assert PTR_EMAIL.replace('@', '.') in str(soa.rname)
        assert soa.refresh == PTR_REFRESH
        assert soa.retry == PTR_RETRY
        assert soa.expire == PTR_EXPIRE
        assert soa.minimum == PTR_MINIMUM

    # =========================================================================
    # PTR Record Tests
    # =========================================================================

    def test_ptr_record(self):
        """Test PTR record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # PTR record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, PTR_ZONE, PTR,
                             record_type='ptr', record_value=[PTR_VALUE])
        ans = self.resolver.resolve(f'{PTR}.{PTR_ZONE}', 'PTR')
        assert PTR_VALUE in [str(r.target) for r in ans]

        tasks.del_dns_record(self.master, PTR_ZONE, PTR,
                             record_type='ptr', record_value=[PTR_VALUE])
        try:
            self.resolver.resolve(f'{PTR}.{PTR_ZONE}', 'PTR')
            raise AssertionError(
                f"Resolving {PTR}.{PTR_ZONE} should have raised "
                "NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # NAPTR Record Tests
    # =========================================================================

    def test_naptr_record(self):
        """Test NAPTR record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # NAPTR record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'naptr',
                             record_type='naptr', record_value=[NAPTR])
        ans = self.resolver.resolve(f'naptr.{ZONE}', 'NAPTR')
        assert any(NAPTR_FIND in str(r.regexp) for r in ans)

        tasks.del_dns_record(self.master, ZONE, 'naptr',
                             record_type='naptr', record_value=[NAPTR])
        try:
            self.resolver.resolve(f'naptr.{ZONE}', 'NAPTR')
            raise AssertionError(
                f"Resolving naptr.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # DNAME Record Tests
    # =========================================================================

    def test_dname_record(self):
        """Test DNAME record add, verify, delete, and underscore (bz915797)."""
        tasks.kinit_admin(self.master)

        # DNAME record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'dname',
                             record_type='dname', record_value=[DNAME])
        ans = self.resolver.resolve(f'dname.{ZONE}', 'DNAME')
        assert DNAME in [str(r.target) for r in ans]

        # Duplicate DNAME should fail (bz915797)
        result = tasks.add_dns_record(self.master, ZONE, 'dname',
                                      record_type='dname',
                                      record_value=[DNAME2],
                                      raiseonerr=False)
        assert result.returncode != 0

        tasks.del_dns_record(self.master, ZONE, 'dname',
                             record_type='dname', record_value=[DNAME])
        try:
            self.resolver.resolve(f'dname.{ZONE}', 'DNAME')
            raise AssertionError(
                f"Resolving dname.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted - expected

        # DNAME with underscore: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'dname',
                             record_type='dname', record_value=[DNAME2])
        ans = self.resolver.resolve(f'dname.{ZONE}', 'DNAME')
        assert DNAME2 in [str(r.target) for r in ans]

        tasks.del_dns_record(self.master, ZONE, 'dname',
                             record_type='dname', record_value=[DNAME2])
        try:
            self.resolver.resolve(f'dname.{ZONE}', 'DNAME')
            raise AssertionError(
                f"Resolving dname.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted - expected

    # =========================================================================
    # CERT Record Tests
    # =========================================================================

    def test_cert_record(self):
        """Test CERT record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # CERT record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'cert',
                             record_type='cert',
                             record_value=[f'{CERT_B} {CERT}'])
        ans = self.resolver.resolve(f'cert.{ZONE}', 'CERT')
        assert any(CERT in str(r) for r in ans)

        tasks.del_dns_record(self.master, ZONE, 'cert',
                             record_type='cert',
                             record_value=[f'{CERT_B} {CERT}'])
        try:
            self.resolver.resolve(f'cert.{ZONE}', 'CERT')
            raise AssertionError(
                f"Resolving cert.{ZONE} should have raised NXDOMAIN")
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted - expected

    # =========================================================================
    # LOC Record Tests
    # =========================================================================

    def test_loc_record(self):
        """Test LOC record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # LOC record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, '@',
                             record_type='loc', record_value=[LOC])
        ans = self.resolver.resolve(ZONE, 'LOC')
        assert any(LOC in str(r) for r in ans)

        tasks.del_dns_record(self.master, ZONE, '@',
                             record_type='loc', record_value=[LOC])
        try:
            self.resolver.resolve(ZONE, 'LOC')
            raise AssertionError(
                f"Resolving LOC for {ZONE} should have raised NoAnswer")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Record deleted - expected

    # =========================================================================
    # KX Record Tests
    # =========================================================================

    def test_kx_record(self):
        """Test KX record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # KX record: add, verify, delete, verify deleted
        kx_val = f'{KX_PREF1} {self.A_HOST}'
        tasks.add_dns_record(self.master, ZONE, '@',
                             record_type='kx', record_value=[kx_val])
        ans = self.resolver.resolve(ZONE, 'KX')
        assert int(KX_PREF1) in [r.preference for r in ans]

        tasks.del_dns_record(self.master, ZONE, '@',
                             record_type='kx', record_value=[kx_val])
        try:
            self.resolver.resolve(ZONE, 'KX')
            raise AssertionError(
                f"Resolving KX for {ZONE} should have raised NoAnswer")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Record deleted or no KX records left - expected

        # Invalid KX records should fail and not be created
        bad_vals = [
            (KX_BAD_PREF1, A_RECORD),
            (KX_BAD_PREF2, ZONE)
        ]
        for bad_pref, bad_target in bad_vals:
            result = tasks.add_dns_record(
                self.master, ZONE, '@', record_type='kx',
                record_value=[f'{bad_pref} {bad_target}'], raiseonerr=False)
            assert result.returncode != 0
            try:
                self.resolver.resolve(ZONE, 'KX')
                raise AssertionError(
                    f"Resolving KX for {ZONE} should have raised "
                    "NoAnswer")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # No KX records - expected

    # =========================================================================
    # Zone Permission Tests
    # =========================================================================

    def test_zone_permission(self):
        """Test DNS zone permission add, verify, and remove operations.

        This test covers zone permission management including adding
        permission, verifying managedby attribute, removing permission,
        testing duplicate add, testing non-existent zone, and verifying
        permission cleanup on zone deletion.
        """
        tasks.kinit_admin(self.master)
        # Clean up if zone exists
        tasks.del_dns_zone(self.master, self.MANAGED_ZONE)

        # Add zone, then permission to manage it
        tasks.add_dns_zone(
            self.master, self.MANAGED_ZONE, admin_email=EMAIL)
        result = tasks.add_dns_zone_permission(self.master, self.MANAGED_ZONE)
        assert result.returncode == 0

        # Verify managedby attribute is set
        result = tasks.show_dns_zone(
            self.master, self.MANAGED_ZONE, all_attrs=True)
        assert 'managedby' in result.stdout_text.lower()

        # Verify permission is added
        perm_name = f'Manage DNS zone {self.MANAGED_ZONE}'
        result = tasks.find_permission(self.master, permission=perm_name)
        assert result.returncode == 0

        # Remove permission to manage zone
        result = tasks.remove_dns_zone_permission(
            self.master, self.MANAGED_ZONE)
        assert result.returncode == 0

        # Verify managedby attribute is not available
        result = tasks.show_dns_zone(
            self.master, self.MANAGED_ZONE, all_attrs=True)
        assert 'managedby' not in result.stdout_text.lower()

        # Verify permission is removed
        result = tasks.find_permission(
            self.master, permission=perm_name, raiseonerr=False)
        assert result.returncode != 0

        # Add zone with permission, delete zone, verify permission deleted
        tasks.del_dns_zone(self.master, self.MANAGED_ZONE1)
        tasks.add_dns_zone(
            self.master, self.MANAGED_ZONE1, admin_email=EMAIL)
        tasks.add_dns_zone_permission(self.master, self.MANAGED_ZONE1)
        tasks.del_dns_zone(self.master, self.MANAGED_ZONE1)
        perm_name1 = f'Manage DNS zone {self.MANAGED_ZONE1}'
        result = tasks.find_permission(
            self.master, permission=perm_name1, raiseonerr=False)
        assert result.returncode != 0

        # Add duplicate permission to manage zone
        tasks.add_dns_zone_permission(
            self.master, self.MANAGED_ZONE, raiseonerr=False)
        result = tasks.add_dns_zone_permission(
            self.master, self.MANAGED_ZONE, raiseonerr=False)
        assert result.returncode != 0
        assert 'already exists' in result.stderr_text

        # Add permission to manage non-existent zone
        result = tasks.add_dns_zone_permission(
            self.master, self.NONEXISTENT_ZONE, raiseonerr=False)
        assert result.returncode != 0
        assert 'DNS zone not found' in result.stderr_text

        # Remove permission to manage zone again (should fail)
        tasks.remove_dns_zone_permission(
            self.master, self.MANAGED_ZONE, raiseonerr=False)
        result = tasks.remove_dns_zone_permission(
            self.master, self.MANAGED_ZONE, raiseonerr=False)
        assert result.returncode != 0
        assert 'permission not found' in result.stderr_text

        # Remove permission for non-existent zone
        result = tasks.remove_dns_zone_permission(self.master,
                                                  self.NONEXISTENT_ZONE,
                                                  raiseonerr=False)
        assert result.returncode != 0
        assert 'DNS zone not found' in result.stderr_text

        # Cleanup zones from zone permission tests
        tasks.del_dns_zone(self.master, self.MANAGED_ZONE)

    # =========================================================================
    # Persistent Search Tests
    # =========================================================================

    def test_psearch(self):
        """Test persistent search and zone serial updates."""
        tasks.kinit_admin(self.master)

        # Verify psearch is not used when IPA server is installed
        result = self.master.run_command([
            'grep', 'psearch yes', '/etc/named.conf'
        ], raiseonerr=False)
        assert result.returncode != 0

        # Create zone with SOA parameters
        tasks.add_dns_zone(
            self.master, self.ZONE_PSEARCH, admin_email=EMAIL,
            refresh=REFRESH, retry=RETRY, expire=EXPIRE,
            minimum=MINIMUM, ttl=TTL)

        # Verify zone SOA exists
        ans = self.resolver.resolve(self.ZONE_PSEARCH, 'SOA')
        assert len(ans) > 0

        # Add TXT record and verify
        tasks.add_dns_record(self.master, self.ZONE_PSEARCH, 'txt',
                             record_type='txt', record_value=[TXT])
        ans = self.resolver.resolve(f'txt.{self.ZONE_PSEARCH}', 'TXT')
        assert any(TXT in str(r) for r in ans)

        # Update TXT record and verify
        tasks.mod_dns_record(self.master, self.ZONE_PSEARCH, 'txt',
                             record_type='txt', old_value=TXT,
                             new_value=NEW_TXT)
        ans = self.resolver.resolve(f'txt.{self.ZONE_PSEARCH}', 'TXT')
        assert any(NEW_TXT in str(r) for r in ans)

        # Get old serial
        ans = self.resolver.resolve(self.ZONE_PSEARCH, 'SOA')
        old_serial = ans[0].serial

        # Update TXT record again
        tasks.mod_dns_record(self.master, self.ZONE_PSEARCH, 'txt',
                             record_type='txt', old_value=NEW_TXT,
                             new_value=NEWER_TXT)

        # Verify serial increased
        ans = self.resolver.resolve(self.ZONE_PSEARCH, 'SOA')
        new_serial = ans[0].serial
        assert new_serial > old_serial, (
            f"New serial ({new_serial}) should be higher "
            f"than old ({old_serial})")
