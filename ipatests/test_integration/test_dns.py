#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""This covers tests for dns related feature"""

from __future__ import absolute_import

import re
import time

import dns.resolver
from ipapython.dnsutil import DNSResolver
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


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

    # Test zone configuration
    ZONE = "testzone"
    EMAIL = "ipaqar.redhat.com"
    REFRESH = 303
    RETRY = 101
    EXPIRE = 1202
    MINIMUM = 33
    TTL = 55
    BAD_NUM = 12345678901234

    # A record values
    A_RECORD = "1.2.3.4"
    MULTI_A_RECORD1 = "1.2.3.4"
    MULTI_A_RECORD2 = "2.3.4.5"

    # AAAA record values
    AAAA = "fec0:0:a10:6000:10:16ff:fe98:193"
    AAAA_BAD1 = "bada:aaaa:real:ly:bad:dude:extr:a"
    AAAA_BAD2 = "aaaa:bbbb:cccc:dddd:eeee:fffff"

    # AFSDB record values
    AFSDB = "green.femto.edu."

    # CNAME record values
    CNAME = "m.l.k."

    # TXT record values
    TXT = "none=1.2.3.4"

    # SRV record values
    SRV_A = "0 100 389"
    SRV = "why.go.here.com."

    # NAPTR record values
    NAPTR = '100 10 U E2U+msg !^.*$!mailto:info@example.com! .'
    NAPTR_FIND = "info@example.com"

    # DNAME record values
    DNAME = None  # Will be set in setup
    DNAME2 = None  # Will be set in setup

    # CERT record values
    CERT_B = "1 1 1"
    CERT = "F835EDA21E94B565716F"

    # LOC record values
    LOC = "37 23 30.900 N 121 59 19.000 W 7.00m 100.00m 100.00m 2.00m"
    EXPECTED_IPA_LOC_OUTPUT = \
        "37 23 30.900 N 121 59 19.000 W 7.00 100.00 100.00 2.00"
    EXPECTED_DIG_LOC_OUTPUT = \
        "37 23 30.900 N 121 59 19.000 W 7.00m 100m 100m 2m"

    # KX record values
    KX_PREF1 = "1234"
    KX_BAD_PREF1 = "-1"
    KX_BAD_PREF2 = "123345678"
    A_HOST = None  # Will be set in setup

    # PTR zone configuration
    PTR_OCTET = "4.4.4"
    PTR_ZONE = None  # Will be set in setup
    PTR = "8"
    PTR_VALUE = "in.awesome.domain."
    PTR_EMAIL = "ipaqar.redhat.com"
    PTR_REFRESH = 393
    PTR_RETRY = 191
    PTR_EXPIRE = 1292
    PTR_MINIMUM = 39
    PTR_TTL = 59
    PTR_BAD_NUM = 12345678901234
    BAD_PTR_ZONE = "1.2.3.in-addr.arpa."

    # Zone permission values
    MANAGED_ZONE = None  # Will be set in setup
    MANAGED_ZONE1 = None  # Will be set in setup
    NONEXISTENT_ZONE = None  # Will be set in setup

    # Persistent search values
    ZONE_PSEARCH = None  # Will be set in setup
    NEW_TXT = "newip=5.6.7.8"
    NEWER_TXT = "newip=8.7.6.5"

    # MX record values
    MX = None  # Will be set in setup

    @classmethod
    def install(cls, mh):
        super(TestDNSAcceptance, cls).install(mh)
        # Set domain-dependent values
        cls.DNAME = f"bar.{cls.ZONE}."
        cls.DNAME2 = f"bar_underscore.{cls.ZONE}."
        cls.PTR_ZONE = f"{cls.PTR_OCTET}.in-addr.arpa."
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
        for zone in [cls.ZONE, cls.PTR_ZONE, cls.MANAGED_ZONE,
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
            self.master, self.ZONE,
            admin_email=self.EMAIL,
            refresh=self.REFRESH,
            retry=self.RETRY,
            expire=self.EXPIRE,
            minimum=self.MINIMUM,
            ttl=self.TTL
        )
        # Verify the new zone was created and is findable
        result = tasks.find_dns_zone(self.master, self.ZONE, all_attrs=True)
        assert self.ZONE in result.stdout_text

        # Verify DNS server returns correct SOA attributes using DNS API
        self.master.run_command(['ipactl', 'restart'])
        time.sleep(5)
        soa = self.resolver.resolve(self.ZONE, 'SOA')[0]
        assert self.master.hostname in str(soa.mname)
        assert self.EMAIL.replace('@', '.') in str(soa.rname)
        assert soa.refresh == self.REFRESH
        assert soa.retry == self.RETRY
        assert soa.expire == self.EXPIRE
        assert soa.minimum == self.MINIMUM

    # =========================================================================
    # A Record Tests
    # =========================================================================

    def test_a_record(self):
        """Test A record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # Single A record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, 'allll',
                             record_type='a', record_value=self.A_RECORD)
        ans = self.resolver.resolve(f'allll.{self.ZONE}', 'A')
        assert self.A_RECORD in [r.address for r in ans]

        tasks.del_dns_record(self.master, self.ZONE, 'allll',
                             record_type='a', record_value=self.A_RECORD)
        try:
            ans = self.resolver.resolve(f'allll.{self.ZONE}', 'A')
            assert self.A_RECORD not in [r.address for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

        # Multiple A records: add, verify, delete, verify deleted
        multi_recs = [self.MULTI_A_RECORD1, self.MULTI_A_RECORD2]
        tasks.add_dns_record(self.master, self.ZONE, 'aa2',
                             record_type='a', record_value=multi_recs)
        ans = self.resolver.resolve(f'aa2.{self.ZONE}', 'A')
        assert self.MULTI_A_RECORD1 in [r.address for r in ans]
        assert self.MULTI_A_RECORD2 in [r.address for r in ans]

        tasks.del_dns_record(self.master, self.ZONE, 'aa2',
                             record_type='a', record_value=multi_recs)
        try:
            ans = self.resolver.resolve(f'aa2.{self.ZONE}', 'A')
            assert self.MULTI_A_RECORD1 not in [r.address for r in ans]
            assert self.MULTI_A_RECORD2 not in [r.address for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Records deleted, name no longer exists - expected

    # =========================================================================
    # AAAA Record Tests
    # =========================================================================

    def test_aaaa_record(self):
        """Test AAAA record add, verify, delete, and invalid values."""
        tasks.kinit_admin(self.master)

        # AAAA record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, 'aaaa',
                             record_type='aaaa', record_value=self.AAAA)
        ans = self.resolver.resolve(f'aaaa.{self.ZONE}', 'AAAA')
        assert self.AAAA in [r.address for r in ans]

        tasks.del_dns_record(self.master, self.ZONE, 'aaaa',
                             record_type='aaaa', record_value=self.AAAA)
        try:
            ans = self.resolver.resolve(f'aaaa.{self.ZONE}', 'AAAA')
            assert self.AAAA not in [r.address for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

        # Invalid AAAA record should fail and not be created
        result = tasks.add_dns_record(self.master, self.ZONE, 'aaaab',
                                      record_type='aaaa',
                                      record_value=self.AAAA_BAD1,
                                      raiseonerr=False)
        assert result.returncode != 0
        try:
            ans = self.resolver.resolve(f'aaaab.{self.ZONE}', 'AAAA')
            assert self.AAAA_BAD1 not in [r.address for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record was never created - expected

    # =========================================================================
    # AFSDB Record Tests
    # =========================================================================

    def test_afsdb_record(self):
        """Test AFSDB record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # AFSDB record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, 'afsdb',
                             record_type='afsdb',
                             record_value=f'0 {self.AFSDB}')
        ans = self.resolver.resolve(f'afsdb.{self.ZONE}', 'AFSDB')
        assert self.AFSDB in [str(r.hostname) for r in ans]

        tasks.del_dns_record(self.master, self.ZONE, 'afsdb',
                             record_type='afsdb',
                             record_value=f'0 {self.AFSDB}')
        try:
            ans = self.resolver.resolve(f'afsdb.{self.ZONE}', 'AFSDB')
            assert self.AFSDB not in [str(r.hostname) for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # CNAME Record Tests
    # =========================================================================

    def test_cname_record(self):
        """Test CNAME record add, verify, delete, and duplicate (bz915807)."""
        tasks.kinit_admin(self.master)

        # CNAME record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, 'cname',
                             record_type='cname', record_value=self.CNAME)
        ans = self.resolver.resolve(f'cname.{self.ZONE}', 'CNAME')
        assert self.CNAME in [str(r.target) for r in ans]

        # Duplicate CNAME should fail and not be created (bz915807)
        result = tasks.add_dns_record(self.master, self.ZONE, 'cname',
                                      record_type='cname',
                                      record_value='a.b.c', raiseonerr=False)
        assert result.returncode != 0
        ans = self.resolver.resolve(f'cname.{self.ZONE}', 'CNAME')
        assert 'a.b.c' not in [str(r.target) for r in ans]

        tasks.del_dns_record(self.master, self.ZONE, 'cname',
                             record_type='cname', record_value=self.CNAME)
        try:
            ans = self.resolver.resolve(f'cname.{self.ZONE}', 'CNAME')
            assert self.CNAME not in [str(r.target) for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # TXT Record Tests
    # =========================================================================

    def test_txt_record(self):
        """Test TXT record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # TXT record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, 'txt',
                             record_type='txt', record_value=self.TXT)
        ans = self.resolver.resolve(f'txt.{self.ZONE}', 'TXT')
        assert any(self.TXT in str(r) for r in ans)

        tasks.del_dns_record(self.master, self.ZONE, 'txt',
                             record_type='txt', record_value=self.TXT)
        try:
            ans = self.resolver.resolve(f'txt.{self.ZONE}', 'TXT')
            assert not any(self.TXT in str(r) for r in ans)
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # SRV Record Tests
    # =========================================================================

    def test_srv_record(self):
        """Test SRV record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # SRV record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, '_srv',
                             record_type='srv',
                             record_value=f'{self.SRV_A} {self.SRV}')
        ans = self.resolver.resolve(f'_srv.{self.ZONE}', 'SRV')
        assert self.SRV in [str(r.target) for r in ans]

        tasks.del_dns_record(self.master, self.ZONE, '_srv', del_all=True)
        try:
            ans = self.resolver.resolve(f'_srv.{self.ZONE}', 'SRV')
            assert self.SRV not in [str(r.target) for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # MX Record Tests
    # =========================================================================

    def test_mx_record(self):
        """Test MX record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # MX record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, '@',
                             record_type='mx',
                             record_value=f'10 {self.MX}.')
        ans = self.resolver.resolve(self.ZONE, 'MX')
        assert f'{self.MX}.' in [str(r.exchange) for r in ans]

        tasks.del_dns_record(self.master, self.ZONE, '@',
                             record_type='mx',
                             record_value=f'10 {self.MX}.')
        try:
            ans = self.resolver.resolve(self.ZONE, 'MX')
            assert f'{self.MX}.' not in [str(r.exchange) for r in ans]
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
        tasks.del_dns_zone(self.master, self.PTR_ZONE)

        # Create PTR zone with all SOA parameters
        tasks.add_dns_zone(
            self.master, self.PTR_ZONE,
            skip_overlap_check=True,
            admin_email=self.PTR_EMAIL,
            refresh=self.PTR_REFRESH,
            retry=self.PTR_RETRY,
            expire=self.PTR_EXPIRE,
            minimum=self.PTR_MINIMUM,
            ttl=self.PTR_TTL
        )

        # Verify PTR zone gets created with the correct attributes
        result = tasks.find_dns_zone(
            self.master, self.PTR_ZONE, all_attrs=True)
        assert self.PTR_ZONE in result.stdout_text

        # Verify PTR zone SOA attributes using DNS resolver
        soa = self.resolver.resolve(self.PTR_ZONE, 'SOA')[0]
        assert self.master.hostname in str(soa.mname)
        assert self.PTR_EMAIL.replace('@', '.') in str(soa.rname)
        assert soa.refresh == self.PTR_REFRESH
        assert soa.retry == self.PTR_RETRY
        assert soa.expire == self.PTR_EXPIRE
        assert soa.minimum == self.PTR_MINIMUM

    # =========================================================================
    # PTR Record Tests
    # =========================================================================

    def test_ptr_record(self):
        """Test PTR record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # PTR record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.PTR_ZONE, self.PTR,
                             record_type='ptr', record_value=self.PTR_VALUE)
        ans = self.resolver.resolve(f'{self.PTR}.{self.PTR_ZONE}', 'PTR')
        assert self.PTR_VALUE in [str(r.target) for r in ans]

        tasks.del_dns_record(self.master, self.PTR_ZONE, self.PTR,
                             record_type='ptr', record_value=self.PTR_VALUE)
        try:
            ans = self.resolver.resolve(f'{self.PTR}.{self.PTR_ZONE}', 'PTR')
            assert self.PTR_VALUE not in [str(r.target) for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # NAPTR Record Tests
    # =========================================================================

    def test_naptr_record(self):
        """Test NAPTR record add, verify, and delete operations."""
        tasks.kinit_admin(self.master)

        # NAPTR record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, 'naptr',
                             record_type='naptr', record_value=self.NAPTR)
        ans = self.resolver.resolve(f'naptr.{self.ZONE}', 'NAPTR')
        assert any(self.NAPTR_FIND in str(r.regexp) for r in ans)

        tasks.del_dns_record(self.master, self.ZONE, 'naptr',
                             record_type='naptr', record_value=self.NAPTR)
        try:
            ans = self.resolver.resolve(f'naptr.{self.ZONE}', 'NAPTR')
            assert not any(self.NAPTR_FIND in str(r.regexp) for r in ans)
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted, name no longer exists - expected

    # =========================================================================
    # DNAME Record Tests
    # =========================================================================

    def test_dname_record(self):
        """Test DNAME record add, verify, delete, and underscore (bz915797)."""
        tasks.kinit_admin(self.master)

        # DNAME record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, 'dname',
                             record_type='dname', record_value=self.DNAME)
        ans = self.resolver.resolve(f'dname.{self.ZONE}', 'DNAME')
        assert self.DNAME in [str(r.target) for r in ans]

        # Duplicate DNAME should fail (bz915797)
        result = tasks.add_dns_record(self.master, self.ZONE, 'dname',
                                      record_type='dname',
                                      record_value=self.DNAME2,
                                      raiseonerr=False)
        assert result.returncode != 0

        tasks.del_dns_record(self.master, self.ZONE, 'dname',
                             record_type='dname', record_value=self.DNAME)
        try:
            ans = self.resolver.resolve(f'dname.{self.ZONE}', 'DNAME')
            assert self.DNAME not in [str(r.target) for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted - expected

        # DNAME with underscore: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, self.ZONE, 'dname',
                             record_type='dname', record_value=self.DNAME2)
        ans = self.resolver.resolve(f'dname.{self.ZONE}', 'DNAME')
        assert self.DNAME2 in [str(r.target) for r in ans]

        tasks.del_dns_record(self.master, self.ZONE, 'dname',
                             record_type='dname', record_value=self.DNAME2)
        try:
            ans = self.resolver.resolve(f'dname.{self.ZONE}', 'DNAME')
            assert self.DNAME2 not in [str(r.target) for r in ans]
        except dns.resolver.NXDOMAIN:
            pass  # Record deleted - expected

    # =========================================================================
    # CERT Record Tests
    # =========================================================================

    def test_cert_record(self):
        """Test CERT record add, verify, and delete operations.

        This test covers CERT record management including adding,
        verifying via IPA and dig, and deleting records.
        """
        tasks.kinit_admin(self.master)
        # Add record of type CERT
        tasks.add_dns_record(self.master, self.ZONE, 'cert',
                             record_type='cert',
                             record_value=f'{self.CERT_B} {self.CERT}')

        # Verify CERT record was saved correctly
        result = tasks.find_dns_record(self.master, self.ZONE, 'cert')
        assert self.CERT in result.stdout_text

        # Verify dig can find the CERT record
        result = self.master.run_command([
            'dig', '+short', f'cert.{self.ZONE}', 'CERT',
            '@' + self.master.hostname
        ])
        assert self.CERT in result.stdout_text

        # Delete record of type CERT
        tasks.del_dns_record(self.master, self.ZONE, 'cert',
                             record_type='cert',
                             record_value=f'{self.CERT_B} {self.CERT}')

        # Verify CERT record was deleted
        result = tasks.find_dns_record(self.master, self.ZONE, 'cert',
                                       raiseonerr=False)
        assert result.returncode != 0

        # Verify dig cannot find the deleted CERT record
        time.sleep(5)
        result = self.master.run_command([
            'dig', '+short', f'cert.{self.ZONE}', 'CERT',
            '@' + self.master.hostname
        ])
        assert result.stdout_text.strip() == ""

    # =========================================================================
    # LOC Record Tests
    # =========================================================================

    def test_loc_record(self):
        """Test LOC record add, verify, and delete operations.

        This test covers LOC record management including adding,
        verifying via IPA and dig, and deleting records.
        """
        tasks.kinit_admin(self.master)
        # Add record of type LOC
        tasks.add_dns_record(self.master, self.ZONE, '@',
                             record_type='loc', record_value=self.LOC)

        # Verify LOC record was saved correctly
        result = tasks.find_dns_record(
            self.master, self.ZONE, raiseonerr=False
        )
        assert self.EXPECTED_IPA_LOC_OUTPUT in result.stdout_text

        # Verify dig can find the LOC record
        result = self.master.run_command([
            'dig', '+short', self.ZONE, 'LOC', '@' + self.master.hostname
        ])
        assert self.EXPECTED_DIG_LOC_OUTPUT in result.stdout_text

        # Delete record of type LOC
        tasks.del_dns_record(self.master, self.ZONE, '@',
                             record_type='loc', record_value=self.LOC)

        # Verify LOC record was deleted
        result = tasks.find_dns_record(self.master, self.ZONE, 'loc',
                                       raiseonerr=False)
        assert result.returncode != 0

        # Verify dig cannot find the deleted LOC record
        time.sleep(5)
        result = self.master.run_command([
            'dig', '+short', self.ZONE, 'LOC', '@' + self.master.hostname
        ])
        assert result.stdout_text.strip() == ""

    # =========================================================================
    # KX Record Tests
    # =========================================================================

    def test_kx_record(self):
        """Test KX record add, verify, and delete operations.

        This test covers KX record management including adding,
        verifying via IPA and dig, deleting records, and testing bad values.
        """
        tasks.kinit_admin(self.master)
        # Add record of type KX
        tasks.add_dns_record(self.master, self.ZONE, '@',
                             record_type='kx',
                             record_value=f'{self.KX_PREF1} {self.A_HOST}')

        # Verify KX record was saved correctly
        result = tasks.find_dns_record(self.master, self.ZONE)
        assert self.KX_PREF1 in result.stdout_text

        # Verify dig can find the KX record
        result = self.master.run_command([
            'dig', self.ZONE, 'KX', '@' + self.master.hostname
        ])
        assert self.KX_PREF1 in result.stdout_text

        # Delete record of type KX
        tasks.del_dns_record(self.master, self.ZONE, '@',
                             record_type='kx',
                             record_value=f'{self.KX_PREF1} {self.A_HOST}')

        # Verify KX record was deleted
        result = tasks.find_dns_record(self.master, self.ZONE, 'kx',
                                       raiseonerr=False)
        assert result.returncode != 0

        # Verify dig cannot find the deleted KX record
        time.sleep(5)
        result = self.master.run_command([
            'dig', '+short', self.ZONE, 'KX', '@' + self.master.hostname
        ])
        assert result.stdout_text.strip() == ""

        # Fail to add record of type bad KX
        bad_kx_val = f'{self.KX_BAD_PREF1} {self.A_RECORD}'
        result = tasks.add_dns_record(
            self.master, self.ZONE, '@',
            record_type='kx', record_value=bad_kx_val,
            raiseonerr=False)
        assert result.returncode != 0

        # Verify bad KX record was not saved
        result = tasks.find_dns_record(self.master, self.ZONE)
        assert self.KX_BAD_PREF1 not in result.stdout_text

        # Fail to add record of type bad KX part2
        bad_kx_val2 = f'{self.KX_BAD_PREF2} {self.ZONE}'
        result = tasks.add_dns_record(
            self.master, self.ZONE, '@',
            record_type='kx', record_value=bad_kx_val2,
            raiseonerr=False)
        assert result.returncode != 0

        # Verify bad KX record was not saved part2
        result = tasks.find_dns_record(self.master, self.ZONE)
        assert self.KX_BAD_PREF2 not in result.stdout_text

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
            self.master, self.MANAGED_ZONE, admin_email=self.EMAIL)
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
            self.master, self.MANAGED_ZONE1, admin_email=self.EMAIL)
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
        """Test persistent search functionality.

        This test verifies that psearch is not used, creates a zone,
        adds and updates TXT records, and verifies zone serial increases
        on updates.
        """
        tasks.kinit_admin(self.master)
        # Verify psearch is not used or set when IPA server is installed
        result = self.master.run_command([
            'grep', 'psearch yes', '/etc/named.conf'
        ], raiseonerr=False)
        assert result.returncode != 0

        # Clean up if zone exists
        tasks.del_dns_zone(self.master, self.ZONE_PSEARCH)

        # Create a new zone and check the zone with dig
        tasks.add_dns_zone(
            self.master, self.ZONE_PSEARCH,
            admin_email=self.EMAIL,
            refresh=self.REFRESH,
            retry=self.RETRY,
            expire=self.EXPIRE,
            minimum=self.MINIMUM,
            ttl=self.TTL
        )

        # Verify zone with dig
        result = self.master.run_command([
            'dig', self.ZONE_PSEARCH, 'SOA', '+norecurse',
            '@' + self.master.hostname
        ])
        assert self.master.hostname in result.stdout_text

        # Add record of type TXT and check the record with dig
        tasks.add_dns_record(self.master, self.ZONE_PSEARCH, 'txt',
                             record_type='txt', record_value=self.TXT)
        result = self.master.run_command([
            'dig', '+short', f'txt.{self.ZONE_PSEARCH}', 'TXT',
            '@' + self.master.hostname
        ])
        assert self.TXT in result.stdout_text

        # Update records TXT value and check using dig
        tasks.mod_dns_record(self.master, self.ZONE_PSEARCH, 'txt',
                             record_type='txt',
                             old_value=self.TXT,
                             new_value=self.NEW_TXT)
        result = self.master.run_command([
            'dig', '+short', f'txt.{self.ZONE_PSEARCH}', 'TXT',
            '@' + self.master.hostname
        ])
        assert self.NEW_TXT in result.stdout_text

        # Get old serial for comparison
        result = self.master.run_command([
            'dig', self.ZONE_PSEARCH, '+multiline', '-t', 'SOA',
            '@' + self.master.hostname
        ])
        serial_match = re.search(r'(\d+)\s*;\s*serial', result.stdout_text)
        assert serial_match, "Could not find serial in dig output"
        old_serial = int(serial_match.group(1))

        # Update records TXT value and verify zone has new higher serial
        tasks.mod_dns_record(self.master, self.ZONE_PSEARCH, 'txt',
                             record_type='txt',
                             old_value=self.NEW_TXT,
                             new_value=self.NEWER_TXT)

        # Get new serial
        result = self.master.run_command([
            'dig', self.ZONE_PSEARCH, '+multiline', '-t', 'SOA',
            '@' + self.master.hostname
        ])
        serial_match = re.search(r'(\d+)\s*;\s*serial', result.stdout_text)
        assert serial_match, "Could not find serial in dig output"
        new_serial = int(serial_match.group(1))

        assert new_serial > old_serial, (
            f"New serial ({new_serial}) should be higher "
            f"than old ({old_serial})")

        # Cleanup zones from psearch tests
        tasks.del_dns_zone(self.master, self.ZONE_PSEARCH)

    # =========================================================================
    # DNS Cleanup Tests
    # =========================================================================

    def test_dns_cleanup(self):
        """Delete the zones created for this test."""
        tasks.kinit_admin(self.master)
        # Delete the main zone
        tasks.del_dns_zone(self.master, self.ZONE)
        result = tasks.find_dns_zone(
            self.master, self.ZONE, raiseonerr=False)
        assert result.returncode != 0

        # Delete the PTR zone
        tasks.del_dns_zone(self.master, self.PTR_ZONE)
        result = tasks.find_dns_zone(
            self.master, self.PTR_ZONE, raiseonerr=False)
        assert result.returncode != 0
