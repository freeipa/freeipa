#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""This covers tests for dns related feature"""

from __future__ import absolute_import

import time
import dns.exception
import dns.resolver
from ipapython.dn import DN
from ipapython.dnsutil import DNSResolver
from ipatests.pytest_ipa.integration import tasks, skip_if_fips
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

# TSIG key configuration for dynamic DNS updates (hmac-md5)
KEY_NAME = "selfupdate"
KEY_SECRET = "05Fu1ACKv1/1Ag=="
KEY_CONFIG = f'''key {KEY_NAME} {{
    algorithm hmac-md5;
    secret "{KEY_SECRET}";
}};
'''

# nsupdate template for deleting A record
NSUPDATE_DELETE_A_TEMPLATE = """debug
update delete {hostname} IN A {ip}
send
"""

# nsupdate template for adding AAAA record
NSUPDATE_ADD_AAAA_TEMPLATE = """debug
update add {hostname} {ttl} IN AAAA {ip}
send
"""

# nsupdate template for adding A record with TSIG key
NSUPDATE_ADD_A_WITH_KEY_TEMPLATE = """server {server}
zone {zone}
key {key_name} {key_secret}
update add {hostname} {ttl} IN A {ip}
send
"""


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
        tasks.add_dns_record(self.master, ZONE, 'allll', 'a', [A_RECORD])
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
        tasks.add_dns_record(self.master, ZONE, 'aa2', 'a', multi_recs)
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
        """Test AAAA record add, verify, delete, and invalid values.
        """
        tasks.kinit_admin(self.master)

        # AAAA record: add, verify, delete, verify deleted
        tasks.add_dns_record(self.master, ZONE, 'aaaa', 'aaaa', [AAAA])
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
                                      'aaaa', [AAAA_BAD1], raiseonerr=False)
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
                             'afsdb', [f'0 {AFSDB}'])
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
        tasks.add_dns_record(self.master, ZONE, 'cname', 'cname', [CNAME])
        ans = self.resolver.resolve(f'cname.{ZONE}', 'CNAME')
        assert CNAME in [str(r.target) for r in ans]

        # Duplicate CNAME should fail and not be created (bz915807)
        result = tasks.add_dns_record(self.master, ZONE, 'cname',
                                      'cname', ['a.b.c'], raiseonerr=False)
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
        tasks.add_dns_record(self.master, ZONE, 'txt', 'txt', [TXT])
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
                             'srv', [f'{SRV_A} {SRV}'])
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
                             'mx', [f'10 {self.MX}.'])
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
        tasks.add_dns_record(self.master, PTR_ZONE, PTR, 'ptr', [PTR_VALUE])
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
        tasks.add_dns_record(self.master, ZONE, 'naptr', 'naptr', [NAPTR])
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
        tasks.add_dns_record(self.master, ZONE, 'dname', 'dname', [DNAME])
        ans = self.resolver.resolve(f'dname.{ZONE}', 'DNAME')
        assert DNAME in [str(r.target) for r in ans]

        # Duplicate DNAME should fail (bz915797)
        result = tasks.add_dns_record(self.master, ZONE, 'dname',
                                      'dname', [DNAME2], raiseonerr=False)
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
        tasks.add_dns_record(self.master, ZONE, 'dname', 'dname', [DNAME2])
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
                             'cert', [f'{CERT_B} {CERT}'])
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
        tasks.add_dns_record(self.master, ZONE, '@', 'loc', [LOC])
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
        tasks.add_dns_record(self.master, ZONE, '@', 'kx', [kx_val])
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
                self.master, ZONE, '@', 'kx',
                [f'{bad_pref} {bad_target}'], raiseonerr=False)
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
        tasks.add_dns_record(
            self.master, self.ZONE_PSEARCH, 'txt', 'txt', [TXT])
        ans = self.resolver.resolve(f'txt.{self.ZONE_PSEARCH}', 'TXT')
        assert any(TXT in str(r) for r in ans)

        # Update TXT record and verify
        tasks.mod_dns_record(self.master, self.ZONE_PSEARCH, 'txt',
                             f'--txt-rec={TXT}', f'--txt-data={NEW_TXT}')
        ans = self.resolver.resolve(f'txt.{self.ZONE_PSEARCH}', 'TXT')
        assert any(NEW_TXT in str(r) for r in ans)

        # Get old serial
        ans = self.resolver.resolve(self.ZONE_PSEARCH, 'SOA')
        old_serial = ans[0].serial

        # Update TXT record again
        tasks.mod_dns_record(self.master, self.ZONE_PSEARCH, 'txt',
                             f'--txt-rec={NEW_TXT}', f'--txt-data={NEWER_TXT}')

        # Verify serial increased
        ans = self.resolver.resolve(self.ZONE_PSEARCH, 'SOA')
        new_serial = ans[0].serial
        assert new_serial > old_serial, (
            f"New serial ({new_serial}) should be higher "
            f"than old ({old_serial})")


class TestDNSMisc(IntegrationTest):
    """Tests for DNS related bugzilla fixes.

    This test class covers various DNS bugzilla fixes ported from
    the shell-based test suite (t.dns_bz.sh).

    Tests are ordered to match the sequence in the original bash test file.
    """
    topology = 'line'
    num_clients = 0

    # Test zone constants
    ZONE = "newbzzone"
    EMAIL = "ipaqar.redhat.com"

    @classmethod
    def install(cls, mh):
        super(TestDNSMisc, cls).install(mh)
        tasks.kinit_admin(cls.master)
        # Create test zone for bug tests
        tasks.add_dns_zone(
            cls.master, cls.ZONE,
            skip_overlap_check=True,
            admin_email=cls.EMAIL,
            raiseonerr=False
        )
        # Setup DNS resolver for test queries
        cls.resolver = DNSResolver()
        cls.resolver.nameservers = [cls.master.ip]
        cls.resolver.lifetime = 10

    @classmethod
    def uninstall(cls, mh):
        tasks.kinit_admin(cls.master)
        # Cleanup test zone
        tasks.del_dns_zone(cls.master, cls.ZONE)
        super(TestDNSMisc, cls).uninstall(mh)

    def test_dns_local_zone_query_no_ldap_error(self):
        """Test DNS server handles local zone queries without LDAP errors.

        Verify that DNS queries to local zone with invalid characters
        (like commas) do not cause LDAP connection loss or DN syntax errors.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=814495
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        # Restart IPA and wait for services
        self.master.run_command(['ipactl', 'restart'])

        # Query with invalid characters - should not cause LDAP errors
        try:
            self.resolver.resolve(f'abc,xyz.{domain}', 'A')
        except dns.exception.DNSException:
            pass
        time.sleep(10)

        # Check recent logs for LDAP errors (use journalctl for compatibility)
        result = self.master.run_command([
            'journalctl', '-u', 'named', '-n', '40', '--no-pager'
        ], raiseonerr=False)
        log_tail = result.stdout_text
        ldap_err1 = 'connection to the ldap server was lost'
        ldap_err2 = 'LDAP error: Invalid DN syntax'
        assert (ldap_err1 not in log_tail.lower()
                and ldap_err2 not in log_tail), "LDAP error found in logs"

    def test_dns_special_chars_no_crash(self):
        """Test DNS queries with special characters don't cause crash.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=841900
        CVE-2012-3429 bind dyndb ldap named DoS via special chars.
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        # Query with various special characters
        # Using self.resolver which targets self.master.ip
        special_chars = ['$', '@', '"', '(', ')', '..', ';', '\\']
        for char in special_chars:
            try:
                self.resolver.resolve(f'{char}.{domain}', 'A')
            except dns.exception.DNSException:
                pass

        # Check recent logs for crashes (use journalctl for compatibility)
        result = self.master.run_command([
            'journalctl', '-u', 'named', '-n', '40', '--no-pager'
        ], raiseonerr=False)
        log_tail = result.stdout_text
        has_crash = 'REQUIRE' in log_tail and 'failed, back trace' in log_tail
        assert not has_crash and '/var/named/core' not in log_tail, \
            "Crash or core dump found in logs"

    def test_dynamic_update_flag_preserved(self):
        """Test DNS zone dynamic flag is not changed unexpectedly.
        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=766075
        """
        tasks.kinit_admin(self.master)
        zone = "example766075.com"

        try:
            # Create zone with dynamic update enabled
            tasks.add_dns_zone(
                self.master, zone,
                skip_overlap_check=True,
                dynamic_update=True,
                admin_email='admin@example.com'
            )

            # Verify dynamic update is True
            result = tasks.show_dns_zone(self.master, zone)
            assert "Dynamic update: True" in result.stdout_text

            # Modify another attribute, dynamic update should remain True
            tasks.mod_dns_zone(self.master, zone, '--retry=600')
            result = tasks.show_dns_zone(self.master, zone, all_attrs=True)
            assert "Dynamic update: True" in result.stdout_text

            # Explicitly disable dynamic update
            tasks.mod_dns_zone(
                self.master, zone, '--dynamic-update=false'
            )
            result = tasks.show_dns_zone(self.master, zone, all_attrs=True)
            assert "Dynamic update: False" in result.stdout_text

        finally:
            tasks.del_dns_zone(self.master, zone)

    def test_skip_invalid_record_in_zone(self):
        """Test invalid record is skipped instead of refusing entire zone.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=751776
        """
        tasks.kinit_admin(self.master)
        zone = "example751776.com"

        try:
            # Add zone and a valid A record
            tasks.add_dns_zone(
                self.master, zone,
                skip_overlap_check=True,
                admin_email=f'admin@{zone}'
            )
            tasks.add_dns_record(
                self.master, zone, 'foo', 'a', ['10.0.0.1']
            )

            # Verify A record resolves
            result = self.resolver.resolve(f'foo.{zone}', 'A')
            assert '10.0.0.1' in [r.to_text() for r in result]

            # Add a valid KX record
            tasks.add_dns_record(
                self.master, zone, '@', 'kx', [f'1 foo.{zone}']
            )

            # Corrupt the KX record via LDAP (invalid format, no preference)
            ldap = self.master.ldap_connect()
            dn = DN(
                ('idnsname', f'{zone}.'),
                ('cn', 'dns'),
                self.master.domain.basedn
            )
            entry = ldap.get_entry(dn)
            entry['kXRecord'] = [f'foo.{zone}']
            ldap.update_entry(entry)

            time.sleep(5)

            # Verify A record still resolves despite invalid KX record
            result = self.resolver.resolve(f'foo.{zone}', 'A')
            assert '10.0.0.1' in [r.to_text() for r in result]

        finally:
            tasks.del_dns_zone(self.master, zone, raiseonerr=False)

    def test_bool_attributes_encoded_properly(self):
        """Test bool attributes are encoded properly in setattr/addattr.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=797561
        """
        tasks.kinit_admin(self.master)
        zone = "example797561.com"

        try:
            tasks.add_dns_zone(
                self.master, zone,
                skip_overlap_check=True,
                admin_email='admin@example.com'
            )

            # Check initial state (raw output needed for attribute name)
            result = tasks.show_dns_zone(
                self.master, zone, all_attrs=True, raw=True
            )
            assert "idnsallowdynupdate: FALSE" in result.stdout_text

            # setattr should not allow adding when value exists
            result = tasks.mod_dns_zone(
                self.master, zone,
                '--addattr=idnsAllowDynUpdate=true',
                raiseonerr=False
            )
            assert result.returncode != 0
            err_msg = "idnsallowdynupdate: Only one value allowed."
            assert err_msg in result.stderr_text

            # setattr should work
            tasks.mod_dns_zone(
                self.master, zone,
                '--setattr=idnsAllowDynUpdate=true'
            )
            result = tasks.show_dns_zone(
                self.master, zone, all_attrs=True, raw=True
            )
            assert "idnsallowdynupdate: TRUE" in result.stdout_text

        finally:
            tasks.del_dns_zone(self.master, zone)

    def test_admin_email_formatting(self):
        """Test dnszone mod formats administrator's email properly.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=750806
        """
        tasks.kinit_admin(self.master)
        zone = "example750806.com"

        try:
            tasks.add_dns_zone(
                self.master, zone,
                skip_overlap_check=True,
                admin_email='admin@example.com'
            )

            # Modify admin email with dots
            tasks.mod_dns_zone(
                self.master, zone,
                '--admin-email=foo.bar@example.com'
            )

            result = tasks.show_dns_zone(self.master, zone)
            # The dot in foo.bar should be escaped
            assert "foo\\.bar.example.com" in result.stdout_text

        finally:
            tasks.del_dns_zone(self.master, zone)

    def test_dns_zone_allow_query_transfer(self):
        """Test DNS zones load when idnsAllowQuery/idnsAllowTransfer is filled.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=733371
        """
        tasks.kinit_admin(self.master)
        zone = "example733371.com"
        master_ip = self.master.ip

        try:
            # Add zone
            tasks.add_dns_zone(
                self.master, zone,
                skip_overlap_check=True,
                admin_email="admin@example.com"
            )

            # Add a record
            tasks.add_dns_record(
                self.master, zone, 'foo', 'a', ['10.0.1.1']
            )

            # Set allow-query to master IP
            tasks.mod_dns_zone(
                self.master, zone,
                f'--allow-query={master_ip}'
            )
            tasks.restart_named(self.master)

            # Query should work from allowed IP
            result = self.master.run_command([
                'dig', '+short', '-t', 'A', f'foo.{zone}', f'@{master_ip}'
            ])
            assert '10.0.1.1' in result.stdout_text

            # Set allow-query to different IP (not master)
            tasks.mod_dns_zone(
                self.master, zone,
                '--allow-query=10.0.1.1'
            )
            tasks.restart_named(self.master)

            # Query should fail/be refused from master IP
            result = self.master.run_command([
                'dig', '+short', '-t', 'A', f'foo.{zone}', f'@{master_ip}'
            ], raiseonerr=False)
            # Should not return the IP when query is not allowed
            assert '10.0.1.1' not in result.stdout_text

        finally:
            tasks.del_dns_zone(self.master, zone, raiseonerr=False)

    def test_zone_deleted_when_removed_from_ldap(self):
        """Test plugin deletes zone when removed from LDAP with zonerefresh.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=767492
        """
        tasks.kinit_admin(self.master)
        zone = "unknownexample767492.com"

        try:
            tasks.add_dns_zone(
                self.master, zone,
                skip_overlap_check=True,
                admin_email='admin@unknownexample.com'
            )
            tasks.mod_dns_zone(self.master, zone, '--refresh=30')
            tasks.add_dns_record(
                self.master, zone, 'foo', 'a', ['10.0.2.2']
            )

            time.sleep(35)
            # Verify record is resolvable
            ans = self.resolver.resolve(f'foo.{zone}', 'A')
            assert '10.0.2.2' in [r.address for r in ans]

            # Delete zone
            tasks.del_dns_zone(self.master, zone, raiseonerr=True)

            # Verify zone is gone
            result = tasks.find_dns_zone(self.master, zone, raiseonerr=False)
            assert result.returncode != 0

            time.sleep(35)
            # Record should no longer resolve after zone deletion
            try:
                self.resolver.resolve(f'foo.{zone}', 'A')
                raise AssertionError(
                    f"Resolving foo.{zone} should have failed")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                    dns.resolver.NoAnswer):
                pass  # Expected - zone was deleted

        finally:
            tasks.del_dns_zone(self.master, zone)

    def test_auto_ptr_record(self):
        """Test automatic PTR record creation for A and AAAA records.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=767494
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        # IPv4 test variables
        ipv4_rev = "1.1.10.in-addr.arpa."
        ipv4_addr = "10.1.1.10"

        # IPv6 test variables
        ipv6_rev = "7.4.2.2.0.0.0.0.2.5.0.0.0.2.6.2.ip6.arpa."
        ipv6_addr = "2620:52:0:2247:221:5eff:fe86:16b4"
        ipv6_ptr = "4.b.6.1.6.8.e.f.f.f.e.5.1.2.2.0"

        # === IPv4 Test ===
        try:
            tasks.add_dns_zone(
                self.master, ipv4_rev,
                skip_overlap_check=True, admin_email=self.EMAIL
            )
            tasks.add_dns_record(
                self.master, domain, 'foo', 'a', [ipv4_addr],
                '--a-create-reverse'
            )
            result = tasks.show_dns_record(self.master, ipv4_rev, '10')
            assert f"foo.{domain}" in result.stdout_text

            # Duplicate should fail
            result = tasks.add_dns_record(
                self.master, domain, 'foo', 'a', [ipv4_addr],
                '--a-create-reverse', raiseonerr=False
            )
            assert result.returncode != 0
            assert "already exists" in result.stderr_text

        finally:
            for zone, rec in [(ipv4_rev, '10'), (domain, 'foo')]:
                tasks.del_dns_record(
                    self.master, zone, rec, del_all=True, raiseonerr=False
                )
            tasks.del_dns_zone(self.master, ipv4_rev, raiseonerr=False)

        # === IPv6 Test ===
        try:
            tasks.add_dns_zone(
                self.master, ipv6_rev,
                skip_overlap_check=True, admin_email=self.EMAIL
            )
            tasks.add_dns_record(
                self.master, domain, 'bar', 'aaaa', [ipv6_addr],
                '--aaaa-create-reverse'
            )
            result = tasks.show_dns_record(self.master, ipv6_rev, ipv6_ptr)
            assert f"bar.{domain}" in result.stdout_text

            # Duplicate should fail
            result = tasks.add_dns_record(
                self.master, domain, 'bar', 'aaaa', [ipv6_addr],
                '--aaaa-create-reverse', raiseonerr=False
            )
            assert result.returncode != 0
            assert "already exists" in result.stderr_text

        finally:
            for zone, rec in [(ipv6_rev, ipv6_ptr), (domain, 'bar')]:
                tasks.del_dns_record(
                    self.master, zone, rec, del_all=True, raiseonerr=False
                )
            tasks.del_dns_zone(self.master, ipv6_rev, raiseonerr=False)

    def test_serial_number_updates(self):
        """Test DNS zone serial number updates when record changes.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=804619
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        try:
            # Get initial serial number (raw output needed)
            result = tasks.show_dns_zone(
                self.master, domain, all_attrs=True, raw=True
            )
            serial_line = [
                line for line in result.stdout_text.split('\n')
                if 'idnssoaserial' in line.lower()
            ][0]
            initial_serial = int(serial_line.split(':')[1].strip())

            # Add a record
            tasks.add_dns_record(
                self.master, domain, 'dns175', 'a', ['192.168.0.1']
            )

            # Get new serial number
            result = tasks.show_dns_zone(
                self.master, domain, all_attrs=True, raw=True
            )
            serial_line = [
                line for line in result.stdout_text.split('\n')
                if 'idnssoaserial' in line.lower()
            ][0]
            new_serial = int(serial_line.split(':')[1].strip())

            assert new_serial > initial_serial, (
                f"Serial should have increased: "
                f"{initial_serial} -> {new_serial}"
            )

        finally:
            tasks.del_dns_record(
                self.master, domain, 'dns175',
                record_type='a', record_value=['192.168.0.1']
            )

    def test_ns_hostname_requires_a_aaaa(self):
        """Test NS record hostname must have A or AAAA record.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=804562
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        result = tasks.add_dns_record(
            self.master, domain, 'dns176',
            'ns', [f'ns1.shanks.{domain}.'], raiseonerr=False
        )
        assert result.returncode != 0
        assert "does not have a corresponding A/AAAA record" in \
            result.stderr_text

    def test_zone_forwarder_settings(self):
        """Test zone forwarder settings can be modified.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=795414
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        try:
            # Set forwarders
            tasks.mod_dns_zone(
                self.master, domain,
                '--forwarder=10.65.202.128',
                '--forwarder=10.65.202.129',
                '--forward-policy=first'
            )

            # Remove forwarders
            tasks.mod_dns_zone(
                self.master, domain,
                '--forwarder=', '--forward-policy='
            )

        finally:
            # Ensure cleanup happens
            tasks.mod_dns_zone(
                self.master, domain,
                '--forwarder=', '--forward-policy=',
                raiseonerr=False
            )

    def test_soa_serial_length(self):
        """Test correct SOA serial number length during installation.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=805871
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        result = tasks.show_dns_zone(self.master, domain)

        # Extract serial from output
        for line in result.stdout_text.splitlines():
            if 'Serial' in line:
                serial = line.split(':')[1].strip()
                # Serial should be 10 digits (YYYYMMDDNN format)
                assert len(serial) == 10, \
                    f"Serial length should be 10, got {len(serial)}"
                break

    def test_dnsrecord_mod_error_messages(self):
        """Test proper error message in dnsrecord-mod operations.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=804572
        """
        tasks.kinit_admin(self.master)
        zone = "example804572.com"

        try:
            tasks.add_dns_zone(
                self.master, zone,
                skip_overlap_check=True,
                admin_email=self.EMAIL
            )

            # Test error when cname-hostname and cname-rec both provided
            result = tasks.add_dns_record(
                self.master, zone, 'bz804572', 'cname', [''],
                f'--cname-hostname=bz804572.{zone}', raiseonerr=False
            )
            assert result.returncode != 0
            err_msg = ("invalid 'cname_hostname': Raw value of a DNS record "
                       'was already set by "cname_rec" option')
            assert err_msg in result.stderr_text

            # Test error when modifying without specifying record
            result = tasks.mod_dns_record(
                self.master, zone, 'testbz804572',
                '--a-ip-address=1.2.3.4',
                raiseonerr=False
            )
            assert result.returncode != 0
            assert "'a_rec' is required" in result.stderr_text

        finally:
            tasks.del_dns_zone(self.master, zone)

    def test_reverse_dns_creation_option(self):
        """Test option for adding Reverse DNS record upon forward creation.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=772301
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        # IPv4 test variables
        ipv4_addr = "10.1.1.10"
        ipv4_rev = "1.1.10.in-addr.arpa."

        # IPv6 test variables
        ipv6_addr = "2620:52:0:2247:221:5eff:fe86:16b4"
        ipv6_rev = "7.4.2.2.0.0.0.0.2.5.0.0.0.2.6.2.ip6.arpa."
        ipv6_ptr = "4.b.6.1.6.8.e.f.f.f.e.5.1.2.2.0"

        # === IPv4 Test ===
        try:
            tasks.add_dns_zone(
                self.master, ipv4_rev,
                skip_overlap_check=True, admin_email=self.EMAIL
            )
            tasks.add_dns_record(
                self.master, domain, 'myhost', 'a', [ipv4_addr],
                '--a-create-reverse'
            )

            # Verify forward record
            result = tasks.find_dns_record(self.master, domain, 'myhost')
            assert result.returncode == 0

            # Verify reverse record
            result = tasks.find_dns_record(self.master, ipv4_rev, '10')
            assert result.returncode == 0

        finally:
            tasks.del_dns_record(
                self.master, ipv4_rev, '10', del_all=True, raiseonerr=False
            )
            tasks.del_dns_zone(self.master, ipv4_rev, raiseonerr=False)

        # === IPv6 Test ===
        try:
            tasks.add_dns_zone(
                self.master, ipv6_rev,
                skip_overlap_check=True, admin_email=self.EMAIL
            )
            tasks.add_dns_record(
                self.master, domain, 'myhost', 'aaaa', [ipv6_addr],
                '--aaaa-create-reverse'
            )

            # Verify forward record (now has AAAA)
            result = tasks.find_dns_record(self.master, domain, 'myhost')
            assert result.returncode == 0

            # Verify reverse record
            result = tasks.find_dns_record(self.master, ipv6_rev, ipv6_ptr)
            assert result.returncode == 0

        finally:
            for zone, rec in [(ipv6_rev, ipv6_ptr), (domain, 'myhost')]:
                tasks.del_dns_record(
                    self.master, zone, rec, del_all=True, raiseonerr=False
                )
            tasks.del_dns_zone(self.master, ipv6_rev, raiseonerr=False)

    def test_non_ascii_chars_escaping(self):
        """Test bind dyndb ldap escapes non ASCII characters correctly.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=818933
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        # Query with comma in hostname
        try:
            self.resolver.resolve(f'foo,bar.{domain}', 'A')
        except dns.exception.DNSException:
            pass

        # Check logs for handle_connection_error bug (use journalctl)
        result = self.master.run_command([
            'journalctl', '-u', 'named', '-n', '100', '--no-pager'
        ], raiseonerr=False)
        assert 'bug in handle_connection_error' not in result.stdout_text, \
            "Bug in handle_connection_error found"

    def test_forwarder_help_text(self):
        """Test proper help page for forwarder option.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=819635
        """
        tasks.kinit_admin(self.master)

        result = self.master.run_command([
            'ipa', 'dnszone-mod', '--help'
        ])
        # Should mention per-zone forwarders, not global
        assert "global forwarders" not in result.stdout_text.lower() or \
               "per-zone forwarders" in result.stdout_text.lower()

    def test_delete_host_updates_dns(self):
        """Test DNS is updated when deleting host with --updatedns.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=828687
        """
        tasks.kinit_admin(self.master)
        ip_base = self.master.ip.rsplit('.', 1)[0]
        test_ip = f"{ip_base}.252"
        test_zone = "llnewzone."
        # Reverse zone: take first 3 octets, reverse, join
        rev = '.'.join(self.master.ip.split('.')[:3][::-1])
        reverse_zone = f"{rev}.in-addr.arpa."

        try:
            tasks.add_dns_zone(self.master, test_zone, skip_overlap_check=True,
                               admin_email=self.EMAIL)
            self.master.run_command([
                'ipa', 'host-add', f'--ip-address={test_ip}', f'tt.{test_zone}'
            ])

            # Verify PTR record was added
            result = self.master.run_command([
                'ipa', 'dnsrecord-find', reverse_zone, '252'
            ], raiseonerr=False)
            if result.returncode == 0:
                assert test_zone in result.stdout_text

            # Delete host with --updatedns
            self.master.run_command([
                'ipa', 'host-del', f'tt.{test_zone}', '--updatedns'
            ])

        finally:
            self.master.run_command([
                'ipa', 'host-del', f'tt.{test_zone}'
            ], raiseonerr=False)
            tasks.del_dns_zone(self.master, test_zone, raiseonerr=False)

    def test_ns_record_nonfqdn_validation(self):
        """Test NS record validation appends zone name to non-FQDN.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=813380
        """
        tasks.kinit_admin(self.master)
        host_ip = self.master.ip.rsplit('.', 1)[0] + '.253'
        zone = "llnewzone813380.com"
        host = f'nsnew.{zone}'

        try:
            tasks.add_dns_zone(self.master, zone, skip_overlap_check=True,
                               admin_email=self.EMAIL)

            # Create host for NS
            self.master.run_command([
                'ipa', 'host-add', host, f'--ip-address={host_ip}'
            ])

            # Add non-FQDN NS record (should work by appending zone)
            tasks.add_dns_record(self.master, zone, '@', 'ns', ['nsnew'])

            # Verify NS record
            result = tasks.show_dns_record(self.master, zone, '@')
            assert 'nsnew' in result.stdout_text

        finally:
            self.master.run_command([
                'ipa', 'host-del', host, '--updatedns'
            ], raiseonerr=False)
            tasks.del_dns_zone(self.master, zone, raiseonerr=False)

    def test_reverse_zone_creation(self):
        """Test reverse zones are created correctly from IP prefix.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=798493
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        test_cases = [
            ('10.11.12.0/24', '12.11.10.in-addr.arpa.'),
            ('10.11.12.0/20', '11.10.in-addr.arpa.'),
            ('10.11.12.0/16', '11.10.in-addr.arpa.'),
        ]

        for forward, reverse in test_cases:
            try:
                # Create reverse zone from IP (special --name-from-ip option)
                self.master.run_command([
                    'ipa', 'dnszone-add',
                    f'--admin-email=admin@{domain}',
                    f'--name-from-ip={forward}',
                    '--skip-overlap-check'
                ], stdin_text='\n')

                # Verify zone was created
                result = tasks.find_dns_zone(self.master, reverse)
                assert f"Zone name: {reverse}" in result.stdout_text

            finally:
                tasks.del_dns_zone(self.master, reverse)

    def test_rndc_reload_no_crash(self):
        """Test rndc reload does not cause crash with persistent search.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=829728
        """
        tasks.kinit_admin(self.master)

        # Verify named is running
        assert tasks.host_service_active(self.master, 'named')

        # Run rndc reload
        result = self.master.run_command(['rndc', 'reload'])
        assert result.returncode == 0

        # Verify named is still running
        assert tasks.host_service_active(self.master, 'named')

    def test_zone_transfer_non_fqdn(self):
        """Test zone transfers work for certain non-FQDNs.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=829388
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        host = "bz829388"

        try:
            # Enable zone transfers
            tasks.mod_dns_zone(
                self.master, domain,
                "--allow-transfer=any;"
            )

            # Add a CNAME record without FQDN
            tasks.add_dns_record(
                self.master, domain, host, 'cname', [host]
            )

            # Restart IPA
            self.master.run_command(['ipactl', 'restart'])

            # Check zone transfer includes FQDN
            result = self.master.run_command([
                'dig', '-t', 'AXFR', f'@{self.master.hostname}', domain
            ])
            assert f'{host}.{domain}.' in result.stdout_text

        finally:
            tasks.del_dns_record(
                self.master, domain, host,
                record_type='cname', record_value=[host],
                raiseonerr=False
            )
            tasks.mod_dns_zone(
                self.master, domain,
                "--allow-transfer=none;",
                raiseonerr=False
            )

    def test_dname_cname_conflict(self):
        """Test DNAME record validation and conflict with CNAME.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=915805
        """
        tasks.kinit_admin(self.master)
        zone = "newzonebz915805"
        cname = "m.l.k."
        dname = f"bar.{zone}."
        dname2 = f"bar_underscore.{zone}."

        try:
            # Create zone
            tasks.add_dns_zone(
                self.master, zone,
                admin_email=self.EMAIL,
                refresh=303, retry=101,
                expire=1202, minimum=33, ttl=55
            )

            # Add CNAME
            tasks.add_dns_record(
                self.master, zone, 'cname', 'cname', [cname]
            )

            # DNAME on same name should fail (conflicts with CNAME)
            result = tasks.add_dns_record(
                self.master, zone, 'cname', 'dname', [dname], raiseonerr=False
            )
            assert result.returncode != 0

            # DNAME on different name should succeed
            tasks.add_dns_record(
                self.master, zone, 'dname', 'dname', [dname]
            )

            # Second DNAME on same name should fail
            result = tasks.add_dns_record(
                self.master, zone, 'dname', 'dname', [dname2], raiseonerr=False
            )
            assert result.returncode != 0

        finally:
            tasks.del_dns_zone(self.master, zone)

    def test_soa_serial_increments(self):
        """Test SOA serial number increments for external changes.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=840383
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        zone = f"zone840383.{domain}"
        txt_value = "bug test"
        new_txt_value = "Bug Test for 840383"

        try:
            # Add zone
            tasks.add_dns_zone(
                self.master, zone,
                skip_overlap_check=True,
                admin_email=self.EMAIL
            )

            # Add TXT record
            tasks.add_dns_record(
                self.master, zone, 'txt', 'txt', [f'"{txt_value}"']
            )

            # Enable zone transfers
            tasks.mod_dns_zone(
                self.master, zone,
                "--allow-transfer=any;"
            )

            self.master.run_command(['ipactl', 'restart'])

            # Verify TXT record is part of zone transfer
            result = self.master.run_command([
                'dig', f'@{self.master.ip}', '-t', 'AXFR', zone
            ])
            assert 'TXT' in result.stdout_text

            # Get old serial
            result = self.master.run_command([
                'dig', zone, '+multiline', '-t', 'SOA'
            ])
            old_serial = next(
                int(ln.split()[0]) for ln in result.stdout_text.splitlines()
                if 'serial' in ln.lower()
            )

            # Modify TXT record
            tasks.mod_dns_record(
                self.master, zone, 'txt',
                f'--txt-rec="{txt_value}"', f'--txt-data="{new_txt_value}"'
            )

            # Get new serial - should increment after record modification
            result = self.master.run_command([
                'dig', zone, '+multiline', '-t', 'SOA'
            ])
            new_serial = next(
                int(ln.split()[0]) for ln in result.stdout_text.splitlines()
                if 'serial' in ln.lower()
            )
            assert new_serial > old_serial

            # Enable dynamic updates - serial should NOT change
            tasks.mod_dns_zone(
                self.master, zone,
                "--dynamic-update=true"
            )

            # Get current serial - should NOT change for zone attr update
            result = self.master.run_command([
                'dig', zone, '+multiline', '-t', 'SOA'
            ])
            current_serial = next(
                int(ln.split()[0]) for ln in result.stdout_text.splitlines()
                if 'serial' in ln.lower()
            )
            assert current_serial == new_serial

        finally:
            tasks.del_dns_zone(self.master, zone, raiseonerr=False)

    def test_allow_query_transfer_ipv6(self):
        """Test allow-query and allow-transfer with IPv4 and IPv6.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=701677
        """
        tasks.kinit_admin(self.master)
        zone = "example.com"
        ipv4 = self.master.ip
        ipv6_added = False
        temp_ipv6 = '2001:0db8:0:f101::1/64'

        # Get default network interface
        result = self.master.run_command([
            'sh', '-c',
            "/sbin/ip -4 route show | grep ^default | "
            "awk '{print $5}' | head -1"
        ])
        eth = result.stdout_text.strip()

        # Add temporary IPv6 if none exists
        result = self.master.run_command(
            ['ip', 'addr', 'show', 'scope', 'global'], raiseonerr=False
        )
        if 'inet6' not in result.stdout_text:
            self.master.run_command([
                '/sbin/ip', '-6', 'addr', 'add', temp_ipv6, 'dev', eth
            ])
            ipv6_added = True

        # Get IPv6 address
        result = self.master.run_command([
            'sh', '-c',
            "ip addr show scope global | "
            "sed -e's/^.*inet6 \\([^ ]*\\)\\/.*/\\1/;t;d'"
        ])
        ipv6 = result.stdout_text.strip().split('\n')[0]

        try:
            tasks.add_dns_zone(self.master, zone, skip_overlap_check=True,
                               admin_email=self.EMAIL)

            # Test allow-query: IPv4 allowed, IPv6 denied
            tasks.mod_dns_zone(
                self.master, zone,
                f"--allow-query={ipv4};!{ipv6};"
            )
            result = self.master.run_command(
                ['dig', f'@{ipv4}', '-t', 'soa', zone], raiseonerr=False
            )
            assert 'ANSWER SECTION' in result.stdout_text
            result = self.master.run_command(
                ['dig', f'@{ipv6}', '-t', 'soa', zone], raiseonerr=False
            )
            assert 'ANSWER SECTION' not in result.stdout_text

            # Test allow-query: IPv6 allowed, IPv4 denied
            tasks.mod_dns_zone(
                self.master, zone,
                f"--allow-query={ipv6};!{ipv4};"
            )
            result = self.master.run_command(
                ['dig', f'@{ipv4}', '-t', 'soa', zone], raiseonerr=False
            )
            assert 'ANSWER SECTION' not in result.stdout_text
            result = self.master.run_command(
                ['dig', f'@{ipv6}', '-t', 'soa', zone], raiseonerr=False
            )
            assert 'ANSWER SECTION' in result.stdout_text

            # Reset allow-query to any
            tasks.mod_dns_zone(
                self.master, zone, "--allow-query=any;"
            )

            # Test allow-transfer: IPv4 allowed, IPv6 denied
            tasks.mod_dns_zone(
                self.master, zone,
                f"--allow-transfer={ipv4};!{ipv6};"
            )
            result = self.master.run_command(
                ['dig', f'@{ipv4}', zone, 'axfr'], raiseonerr=False
            )
            assert 'Transfer failed' not in result.stdout_text
            result = self.master.run_command(
                ['dig', f'@{ipv6}', zone, 'axfr'], raiseonerr=False
            )
            assert 'Transfer failed' in result.stdout_text

            # Test allow-transfer: IPv6 allowed, IPv4 denied
            tasks.mod_dns_zone(
                self.master, zone,
                f"--allow-transfer={ipv6};!{ipv4};"
            )
            result = self.master.run_command(
                ['dig', f'@{ipv4}', zone, 'axfr'], raiseonerr=False
            )
            assert 'Transfer failed' in result.stdout_text
            result = self.master.run_command(
                ['dig', f'@{ipv6}', zone, 'axfr'], raiseonerr=False
            )
            assert 'Transfer failed' not in result.stdout_text

        finally:
            tasks.del_dns_zone(self.master, zone, raiseonerr=False)
            if ipv6_added:
                self.master.run_command([
                    '/sbin/ip', '-6', 'addr', 'del', temp_ipv6, 'dev', eth
                ], raiseonerr=False)

    @skip_if_fips(reason='hmac-md5 not supported in FIPS mode')
    def test_updatepolicy_zonesub(self):
        """Test BIND with bind-dyndb-ldap works with zonesub updatepolicy.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=921167

        This test verifies that dynamic DNS updates work correctly when
        using the 'zonesub' match type in the update policy. Note that
        this test requires hmac-md5 which is not supported in FIPS mode.
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        realm = self.master.domain.realm

        # Get IP address components for test record
        ip_parts = self.master.ip.split('.')
        test_ip = f'{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.100'

        # Backup named.conf
        self.master.run_command([
            'cp', '/etc/named.conf', '/etc/named.conf.bak'
        ])

        try:
            # Add key to named.conf for dynamic updates
            self.master.run_command([
                'sh', '-c',
                f'echo \'{KEY_CONFIG}\' >> /etc/named.conf'
            ])

            # Update zone policy to include zonesub match type
            update_policy = (
                f'grant {realm} krb5-self * A; '
                f'grant {realm} krb5-self * AAAA; '
                f'grant {realm} krb5-self * SSHFP; '
                'grant selfupdate zonesub A;'
            )
            tasks.mod_dns_zone(
                self.master, domain, f'--update-policy={update_policy}'
            )

            # Restart named to pick up changes
            tasks.restart_named(self.master)

            # Create nsupdate commands file
            nsupdate_content = NSUPDATE_ADD_A_WITH_KEY_TEMPLATE.format(
                server=self.master.hostname,
                zone=domain,
                key_name=KEY_NAME,
                key_secret=KEY_SECRET,
                hostname=f'foobz921167.{domain}.',
                ttl=60,
                ip=test_ip
            )
            self.master.put_file_contents(
                '/tmp/dnsupdate.txt', nsupdate_content
            )

            # Execute nsupdate with zonesub policy and verify NOERROR
            result = self.master.run_command([
                'nsupdate', '-v', '-D', '/tmp/dnsupdate.txt'
            ])
            assert 'NOERROR' in result.stdout_text, \
                'Dynamic update did not return NOERROR'

        finally:
            # Restore original named.conf
            self.master.run_command([
                'cp', '/etc/named.conf.bak', '/etc/named.conf'
            ], raiseonerr=False)

            # Restore original update policy
            original_policy = (
                f'grant {realm} krb5-self * A; '
                f'grant {realm} krb5-self * AAAA; '
                f'grant {realm} krb5-self * SSHFP;'
            )
            tasks.mod_dns_zone(
                self.master, domain, f'--update-policy={original_policy}',
                raiseonerr=False
            )

            # Cleanup test record if it was created
            tasks.del_dns_record(
                self.master, domain, 'foobz921167',
                del_all=True, raiseonerr=False
            )

            # Restart named
            tasks.restart_named(self.master)

    def test_bind_shutdown_ldap_failure(self):
        """Test BIND shuts down correctly when psearch enabled and LDAP fails.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=802375

        This test verifies that named service can be stopped cleanly
        even when LDAP connection is configured with an invalid URI.
        The test modifies named.conf to point to an invalid LDAP URI,
        then verifies that 'rndc stop' works correctly.
        """
        tasks.kinit_admin(self.master)

        # Get realm name with dashes instead of dots for socket path
        realm_inst = self.master.domain.realm.replace('.', '-')

        try:
            # Check named is running
            assert tasks.host_service_active(self.master, 'named')

            # Backup named.conf
            self.master.run_command(['cp', '/etc/named.conf', '/root/'])

            # Comment out the valid LDAP URI and add invalid one
            # The valid URI looks like:
            # uri "ldapi://%2fvar%2frun%2fslapd-REALM.socket";
            sed_pattern = (
                f's|uri "ldapi://%2fvar%2frun%2fslapd-{realm_inst}.socket";'
                f'|#uri "ldapi://%2fvar%2frun%2fslapd-{realm_inst}.socket";|g'
            )
            self.master.run_command([
                'sed', '-i', sed_pattern, '/etc/named.conf'
            ])

            # Add invalid LDAP URI before the commented line
            insert_pattern = (
                f'/ldapi:\\/\\/%2fvar%2frun%2fslapd-{realm_inst}.socket/i '
                'uri "ldapi://127.0.0.1";'
            )
            self.master.run_command([
                'sed', '-i', insert_pattern, '/etc/named.conf'
            ])

            # Restart named with invalid LDAP config
            tasks.restart_named(self.master)

            # Try to stop named with rndc - should work without hanging
            self.master.run_command(['rndc', 'stop'], raiseonerr=False)

            # Wait a moment for service to stop
            time.sleep(5)

            # Verify named is not running (exit code 3 = inactive)
            result = self.master.run_command(
                ['systemctl', 'is-active', 'named'], raiseonerr=False
            )
            assert result.returncode != 0, "named should be stopped"

        finally:
            # Restore original named.conf
            # Remove the invalid URI line
            self.master.run_command([
                'sed', '-i', '/ldapi:\\/\\/127.0.0.1/d', '/etc/named.conf'
            ], raiseonerr=False)

            # Uncomment the original valid URI
            uncomment_pattern = (
                f's|#uri "ldapi://%2fvar%2frun%2fslapd-{realm_inst}.socket";'
                f'|uri "ldapi://%2fvar%2frun%2fslapd-{realm_inst}.socket";|g'
            )
            self.master.run_command([
                'sed', '-i', uncomment_pattern, '/etc/named.conf'
            ], raiseonerr=False)

            # Restart named to restore normal operation
            tasks.restart_named(self.master)

    def test_bind_ldap_reconnect(self):
        """Test reconnect to LDAP when the first connection fails.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=767489

        This test verifies that named service can handle LDAP connection
        failures gracefully. It modifies named.conf to use an invalid LDAP
        URI while blocking LDAP ports with iptables, then restarts named
        to verify it handles the reconnection properly when connectivity
        is restored.
        """
        tasks.kinit_admin(self.master)

        # Get realm name with dashes instead of dots for socket path
        realm_inst = self.master.domain.realm.replace('.', '-')

        # Firewall rich rules to block LDAP ports
        ldap_reject = 'rule family=ipv4 port port=389 protocol=tcp reject'
        ldaps_reject = 'rule family=ipv4 port port=636 protocol=tcp reject'

        try:
            # Check named is running
            assert tasks.host_service_active(self.master, 'named')

            # Backup named.conf
            self.master.run_command(['cp', '/etc/named.conf', '/root/'])

            # Comment out the valid LDAP URI and add invalid one
            sed_pattern = (
                f's|uri "ldapi://%2fvar%2frun%2fslapd-{realm_inst}.socket";'
                f'|#uri "ldapi://%2fvar%2frun%2fslapd-{realm_inst}.socket";|g'
            )
            self.master.run_command([
                'sed', '-i', sed_pattern, '/etc/named.conf'
            ])

            # Add invalid LDAP URI before the commented line
            insert_pattern = (
                f'/ldapi:\\/\\/%2fvar%2frun%2fslapd-{realm_inst}.socket/i '
                'uri "ldapi://127.0.0.1";'
            )
            self.master.run_command([
                'sed', '-i', insert_pattern, '/etc/named.conf'
            ])

            # Block LDAP ports with firewall-cmd to ensure connection fails
            self.master.run_command([
                'firewall-cmd', f'--add-rich-rule={ldap_reject}'
            ])
            self.master.run_command([
                'firewall-cmd', f'--add-rich-rule={ldaps_reject}'
            ])

            # Restart named - it should handle the LDAP connection failure
            tasks.restart_named(self.master)

            # Verify named is still running (may be in degraded state)
            result = self.master.run_command(
                ['systemctl', 'is-active', 'named'], raiseonerr=False
            )
            # Named may be active or activating depending on timing
            assert result.returncode == 0 or 'activating' in result.stdout_text

        finally:
            # Remove firewall rules to restore LDAP connectivity
            self.master.run_command([
                'firewall-cmd', f'--remove-rich-rule={ldap_reject}'
            ], raiseonerr=False)
            self.master.run_command([
                'firewall-cmd', f'--remove-rich-rule={ldaps_reject}'
            ], raiseonerr=False)

            # Restore original named.conf
            # Remove the invalid URI line
            self.master.run_command([
                'sed', '-i', '/ldapi:\\/\\/127.0.0.1/d', '/etc/named.conf'
            ], raiseonerr=False)

            # Uncomment the original valid URI
            uncomment_pattern = (
                f's|#uri "ldapi://%2fvar%2frun%2fslapd-{realm_inst}.socket";'
                f'|uri "ldapi://%2fvar%2frun%2fslapd-{realm_inst}.socket";|g'
            )
            self.master.run_command([
                'sed', '-i', uncomment_pattern, '/etc/named.conf'
            ], raiseonerr=False)

            # Restart named to restore normal operation
            tasks.restart_named(self.master)

    def test_dnsrecord_mod_nonexistent_error(self):
        """Test correct error message when modifying nonexistent DNS record.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=856281
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name

        # Try to modify a non-existent record
        result = tasks.mod_dns_record(
            self.master, domain, 'this.does.not.exist',
            '--txt-rec=foo', raiseonerr=False
        )

        assert result.returncode != 0
        expected_msg = "this.does.not.exist: DNS resource record not found"
        assert expected_msg in result.stderr_text

    def test_zone_without_update_policy(self):
        """Test zone without idnsUpdatePolicy works during zone refresh.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=908780

        As per bind-dyndb-ldap/NEWS, psearch, serial_autoincrement and
        zone_refresh were deprecated and removed. This test verifies
        that zones without idnsUpdatePolicy still work correctly after
        service restart.
        """
        tasks.kinit_admin(self.master)
        zone = "bz908780zone"

        try:
            # Add test zone
            tasks.add_dns_zone(
                self.master, zone,
                admin_email=self.EMAIL
            )

            # Modify zone to remove idnsUpdatePolicy attribute
            tasks.mod_dns_zone(self.master, zone, '--update-policy=')

            # Restart named service
            tasks.restart_named(self.master)

            # Check logs for error message (use journalctl for compatibility)
            result = self.master.run_command([
                'journalctl', '-u', 'named', '-n', '100', '--no-pager'
            ])

            # Verify no error about zone failing to transfer
            err_msg = "unchanged. zone may fail to transfer to slaves"
            assert err_msg not in result.stdout_text

        finally:
            tasks.del_dns_zone(self.master, zone, raiseonerr=False)

    def test_txt_record_with_comma(self):
        """Test dnsrecord works if TXT record data contains comma.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=910460
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        txt_value = (
            'Holmes laughed. "It is quite a pretty little problem," '
            'said he.'
        )
        txt_mod_value = (
            'Holmes laughed. "It is quite a pretty little problem," '
            'said me.'
        )

        try:
            # Add TXT record with comma - should not cause traceback
            result = tasks.add_dns_record(
                self.master, domain, '@', 'txt', [txt_value]
            )
            assert result.returncode == 0

            # Modify TXT record with comma - should not cause traceback
            result = tasks.mod_dns_record(
                self.master, domain, '@',
                f'--txt-rec={txt_value}', f'--txt-data={txt_mod_value}'
            )
            assert result.returncode == 0

        finally:
            # Delete TXT record
            tasks.del_dns_record(
                self.master, domain, '@',
                record_type='txt', record_value=[txt_mod_value],
                raiseonerr=False
            )

    def test_dname_single_value(self):
        """Test DNAME record attribute allows single value only.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=915797

        Verify that adding a second DNAME record to the same name fails
        with appropriate error message.
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        dname1 = f"foo.{domain}"
        dname2 = f"bar.{domain}"

        try:
            # Add first DNAME record
            tasks.add_dns_record(
                self.master, domain, 'dnamebz915797', 'dname', [dname1]
            )

            # Try to add second DNAME record - should fail
            result = tasks.add_dns_record(
                self.master, domain, 'dnamebz915797', 'dname', [dname2],
                raiseonerr=False
            )
            assert result.returncode != 0
            expected_msg = "only one DNAME record is allowed per name"
            assert expected_msg in result.stderr_text

        finally:
            tasks.del_dns_record(
                self.master, domain, 'dnamebz915797',
                del_all=True, raiseonerr=False
            )

    def test_cname_single_value(self):
        """Test CNAME record allows single value only.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=915807

        Verify that adding a second CNAME record to the same name fails
        with appropriate error message.
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        cname1 = f"foo.{domain}"
        cname2 = f"bar.{domain}"

        try:
            # Add first CNAME record
            tasks.add_dns_record(
                self.master, domain, 'cnamebz915807', 'cname', [cname1]
            )

            # Try to add second CNAME record - should fail
            result = tasks.add_dns_record(
                self.master, domain, 'cnamebz915807', 'cname', [cname2],
                raiseonerr=False
            )
            assert result.returncode != 0
            expected_msg = "only one CNAME record is allowed per name"
            assert expected_msg in result.stderr_text

        finally:
            tasks.del_dns_record(
                self.master, domain, 'cnamebz915807',
                del_all=True, raiseonerr=False
            )

    def test_idnszone_schema_no_cn(self):
        """Test cn attribute is not present in idnsZone objectClasses.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=947911

        Verify that 'cn' attribute is removed from idnsZone objectClasses
        in LDAP schema. Note: 'cn' was returned back to idnsRecord to fix
        bug 1167964, so we only check idnsZone.
        """
        tasks.kinit_admin(self.master)

        # Check that cn attribute is not in idnsZone objectClass
        # Use ldif-wrap=no to keep each objectClass on a single line
        result = self.master.run_command([
            'ldapsearch', '-x', '-D',
            'cn=Directory Manager',
            '-w', self.master.config.dirman_password,
            '-b', 'cn=schema', 'objectClasses',
            '-o', 'ldif-wrap=no'
        ])

        # Verify idnsZone objectClass exists and doesn't contain cn attribute
        lines = result.stdout_text.split('\n')
        is_valid = any(
            "NAME 'idnsZone'" in line and ' cn ' not in line
            for line in lines
        )
        assert is_valid, "cn attribute should not be in idnsZone objectClass"

    def test_ptr_sync_preserves_txt_record(self):
        """Test PTR sync deletes only PTR record, preserves TXT record.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=958140

        When PTR record synchronization is enabled and an A record is
        deleted via dynamic update, only the corresponding PTR record
        should be deleted. Other records (like TXT) on the same name
        in the reverse zone should be preserved.
        """
        tasks.kinit_admin(self.master)
        test_zone = "examplebz958140.com"
        reverse_zone = "3.2.1.in-addr.arpa."
        realm = self.master.domain.realm
        hostname = f"testbz958140.{test_zone}"

        try:
            # Add test zones
            tasks.add_dns_zone(
                self.master, test_zone,
                skip_overlap_check=True,
                admin_email=f"hostmaster.{test_zone}"
            )
            tasks.add_dns_zone(
                self.master, reverse_zone,
                skip_overlap_check=True,
                admin_email=f"hostmaster.{reverse_zone}"
            )

            # Reload named so it can serve the new zones
            self.master.run_command(['rndc', 'reload'])

            # Add A record with reverse PTR
            tasks.add_dns_record(
                self.master, test_zone, 'testbz958140', 'a', ['1.2.3.4'],
                '--a-create-reverse'
            )

            # Add TXT record to reverse zone on same name as PTR
            tasks.add_dns_record(
                self.master, reverse_zone, '4', 'txt', ['text']
            )

            # Enable PTR record synchronization
            tasks.mod_dns_zone(
                self.master, test_zone, '--dynamic-update=True'
            )
            tasks.mod_dns_zone(
                self.master, test_zone, '--allow-sync-ptr=True'
            )
            tasks.mod_dns_zone(
                self.master, reverse_zone, '--dynamic-update=True'
            )

            # Add host and get keytab for dynamic updates
            self.master.run_command([
                'ipa', 'host-add', hostname, '--force'
            ])
            self.master.run_command([
                'ipa-getkeytab', '-s', self.master.hostname,
                '-p', f'host/{hostname}@{realm}',
                '-k', '/tmp/bz958140.keytab'
            ])

            self.master.run_command(['rndc', 'reload'])
            self.master.run_command(['ipactl', 'restart'])

            # Use nsupdate to delete A record (should trigger PTR sync)
            nsupdate_content = NSUPDATE_DELETE_A_TEMPLATE.format(
                hostname=hostname, ip='1.2.3.4'
            )
            self.master.put_file_contents('/tmp/nsupdate958140.txt',
                                          nsupdate_content)
            self.master.run_command([
                'kinit', '-k', '-t', '/tmp/bz958140.keytab',
                f'host/{hostname}'
            ])
            self.master.run_command([
                'nsupdate', '-g', '-v', '/tmp/nsupdate958140.txt'
            ], raiseonerr=False)

            tasks.kinit_admin(self.master)

            # Verify A record is deleted
            result = tasks.find_dns_record(
                self.master, test_zone, 'testbz958140', raiseonerr=False
            )
            assert 'A record' not in result.stdout_text

            # Verify PTR record is deleted
            result = self.master.run_command([
                'ipa', 'dnsrecord-find', reverse_zone, '4'
            ], raiseonerr=False)
            assert 'PTR record' not in result.stdout_text

            # Verify TXT record is preserved
            assert 'TXT record' in result.stdout_text

        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'host-del', hostname
            ], raiseonerr=False)
            tasks.del_dns_zone(self.master, test_zone, raiseonerr=False)
            tasks.del_dns_zone(self.master, reverse_zone, raiseonerr=False)
            self.master.run_command(['rm', '-f', '/tmp/bz958140.keytab',
                                     '/tmp/nsupdate958140.txt'],
                                    raiseonerr=False)

    def test_invalid_policy_disables_operations(self):
        """Test invalid policy disables updates, transfers, and queries.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=958141

        When zone policy (update, transfer, or query) contains invalid
        values, the corresponding operation should be disabled/refused.
        """
        tasks.kinit_admin(self.master)
        test_zone = 'example.test'
        realm = self.master.domain.realm
        hostname = f'test.{test_zone}'

        try:
            # Add test zone and get original update policy
            tasks.add_dns_zone(
                self.master, test_zone,
                skip_overlap_check=True,
                admin_email=f'hostmaster.{test_zone}'
            )

            # Get original update policy
            result = self.master.run_command([
                'ipa', 'dnszone-show', test_zone, '--all'
            ])
            original_policy = None
            for line in result.stdout_text.split('\n'):
                if 'BIND update policy:' in line:
                    original_policy = line.split(':', 1)[1].strip()
                    break

            tasks.add_dns_record(
                self.master, test_zone, 'test', 'a', ['1.2.3.4']
            )

            # Test 1: Verify dynamic update works with valid policy
            tasks.mod_dns_zone(
                self.master, test_zone, '--dynamic-update=True'
            )

            self.master.run_command([
                'ipa', 'host-add', hostname
            ])
            self.master.run_command([
                'ipa-getkeytab', '-s', self.master.hostname,
                '-p', f'host/{hostname}@{realm}',
                '-k', '/tmp/bz958141.keytab'
            ])

            self.master.run_command(['rndc', 'reload'])

            # Create nsupdate file to delete A record
            nsupdate_content = NSUPDATE_DELETE_A_TEMPLATE.format(
                hostname=hostname, ip='1.2.3.4'
            )
            self.master.put_file_contents('/tmp/nsupdate958141.txt',
                                          nsupdate_content)

            self.master.run_command([
                'kinit', '-k', '-t', '/tmp/bz958141.keytab',
                f'host/{hostname}'
            ])

            # Dynamic update should succeed with valid policy
            result = self.master.run_command([
                'nsupdate', '-g', '-v', '/tmp/nsupdate958141.txt'
            ], raiseonerr=False)
            assert result.returncode == 0, \
                'Dynamic update should succeed with valid policy'

            # Set invalid update policy
            tasks.kinit_admin(self.master)
            tasks.mod_dns_zone(
                self.master, test_zone, '--update-policy=invalid value'
            )

            # Re-add A record for next test
            tasks.add_dns_record(
                self.master, test_zone, 'test', 'a', ['1.2.3.4']
            )

            # Dynamic update should fail with invalid policy
            self.master.run_command([
                'kinit', '-k', '-t', '/tmp/bz958141.keytab',
                f'host/{hostname}'
            ])
            result = self.master.run_command([
                'nsupdate', '-g', '/tmp/nsupdate958141.txt'
            ], raiseonerr=False)
            assert result.returncode == 2, \
                'Dynamic update should fail with invalid policy'

            # Restore original update policy
            tasks.kinit_admin(self.master)
            tasks.mod_dns_zone(
                self.master, test_zone,
                f'--update-policy={original_policy}'
            )

            # Test 2: Invalid transfer policy disables zone transfers
            tasks.mod_dns_zone(
                self.master, test_zone, '--allow-transfer=any'
            )

            # Verify zone transfer works with valid policy
            result = self.master.run_command([
                'dig', '@127.0.0.1', '-t', 'AXFR', test_zone
            ], raiseonerr=False)
            assert 'Transfer failed' not in result.stdout_text

            # Set invalid transfer policy via LDAP
            ldap = self.master.ldap_connect()
            zone_dn = DN(
                ('idnsname', f'{test_zone}.'),
                ('cn', 'dns'),
                self.master.domain.basedn
            )
            entry = ldap.get_entry(zone_dn)
            entry['idnsAllowTransfer'] = ['192.0.2..0/24']  # Invalid
            ldap.update_entry(entry)

            # Verify zone transfer fails with invalid policy
            result = self.master.run_command([
                'dig', '@127.0.0.1', '-t', 'AXFR', test_zone
            ], raiseonerr=False)
            assert 'Transfer failed' in result.stdout_text

            # Restore valid transfer policy
            tasks.mod_dns_zone(
                self.master, test_zone, '--allow-transfer=none'
            )

            # Test 3: Invalid query policy disables queries
            # First verify query works with valid policy
            result = self.master.run_command([
                'dig', f'test.{test_zone}'
            ], raiseonerr=False)
            assert 'NOERROR' in result.stdout_text

            # Set invalid query policy via LDAP
            entry = ldap.get_entry(zone_dn)
            entry['idnsAllowQuery'] = ['192.0.2..0/24']  # Invalid
            ldap.update_entry(entry)

            # Verify query is refused
            result = self.master.run_command([
                'dig', f'test.{test_zone}'
            ], raiseonerr=False)
            assert 'REFUSED' in result.stdout_text

            # Restore valid query policy
            tasks.mod_dns_zone(
                self.master, test_zone, '--allow-query=any'
            )

        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'host-del', hostname
            ], raiseonerr=False)
            tasks.del_dns_zone(self.master, test_zone, raiseonerr=False)
            self.master.run_command([
                'rm', '-f', '/tmp/bz958141.keytab', '/tmp/nsupdate958141.txt'
            ], raiseonerr=False)

    def test_ptr_sync_ipv6(self):
        """Test PTR record synchronization works with IPv6 addresses.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=962814

        Verify that when AAAA record is added via dynamic update with
        PTR sync enabled, the corresponding PTR record is created in
        the IPv6 reverse zone.
        """
        tasks.kinit_admin(self.master)
        test_zone = "examplebz962814.com"
        # Reverse zone for 1:2:3:4:5:6::/96
        reverse_zone = (
            "6.0.0.0.5.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa."
        )
        realm = self.master.domain.realm
        hostname = f"test.{test_zone}"

        try:
            # Add test zones
            tasks.add_dns_zone(
                self.master, test_zone,
                skip_overlap_check=True,
                admin_email=f"hostmaster.{test_zone}"
            )
            tasks.add_dns_zone(
                self.master, reverse_zone,
                skip_overlap_check=True,
                admin_email=f"hostmaster.{reverse_zone}"
            )

            # Enable PTR record synchronization
            tasks.mod_dns_zone(
                self.master, test_zone, '--dynamic-update=True'
            )
            tasks.mod_dns_zone(
                self.master, test_zone, '--allow-sync-ptr=True'
            )
            tasks.mod_dns_zone(
                self.master, reverse_zone, '--dynamic-update=True'
            )

            # Add host and get keytab
            self.master.run_command([
                'ipa', 'host-add', hostname, '--force'
            ])
            self.master.run_command([
                'ipa-getkeytab', '-s', self.master.hostname,
                '-p', f'host/{hostname}@{realm}',
                '-k', '/tmp/bz962814.keytab'
            ])

            self.master.run_command(['rndc', 'reload'])

            # Use nsupdate to add AAAA record
            nsupdate_content = NSUPDATE_ADD_AAAA_TEMPLATE.format(
                hostname=hostname, ttl=3600, ip='1:2:3:4:5:6:7:8'
            )
            self.master.put_file_contents('/tmp/nsupdate962814.txt',
                                          nsupdate_content)
            self.master.run_command([
                'kinit', '-k', '-t', '/tmp/bz962814.keytab',
                f'host/{hostname}'
            ])

            time.sleep(60)
            self.master.run_command([
                'nsupdate', '-g', '/tmp/nsupdate962814.txt'
            ])

            tasks.kinit_admin(self.master)

            # Verify AAAA record was added
            result = tasks.find_dns_record(
                self.master, test_zone, 'test', raiseonerr=False
            )
            assert 'AAAA record' in result.stdout_text

            # Verify PTR record was created in reverse zone
            # PTR for 1:2:3:4:5:6:7:8 should be at 8.0.0.0.7.0.0.0
            result = self.master.run_command([
                'ipa', 'dnsrecord-find', reverse_zone, '8.0.0.0.7.0.0.0'
            ], raiseonerr=False)
            assert 'PTR record' in result.stdout_text

        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'host-del', hostname
            ], raiseonerr=False)
            tasks.del_dns_zone(self.master, test_zone, raiseonerr=False)
            tasks.del_dns_zone(self.master, reverse_zone, raiseonerr=False)
            self.master.run_command(['rm', '-f', '/tmp/bz962814.keytab',
                                     '/tmp/nsupdate962814.txt'],
                                    raiseonerr=False)

    def test_ipv6_private_reverse_zone(self):
        """Test serving reverse zones for IPv6 private ranges.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=962815

        Verify that reverse zones for IPv6 private/documentation ranges
        (like 2001:db8::/32) can be served without manual changes to
        named.conf. These are in the automatic empty zones list.
        """
        tasks.kinit_admin(self.master)
        # 2001:db8::/32 documentation prefix reverse zone
        reverse_zone = "8.b.d.0.1.0.0.2.ip6.arpa"
        test_record = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
        test_ptr = "test.example.com"
        test_ipv6 = "2001:0db8::1"

        try:
            # Add reverse zone for IPv6 documentation prefix
            tasks.add_dns_zone(
                self.master, reverse_zone,
                admin_email=f"hostmaster.{reverse_zone}"
            )

            # Add PTR record
            tasks.add_dns_record(
                self.master, f"{reverse_zone}.", test_record,
                'ptr', [test_ptr]
            )

            self.master.run_command(['ipactl', 'restart'])

            # Verify reverse lookup works
            result = self.master.run_command([
                'dig', '-x', test_ipv6
            ])
            assert test_record in result.stdout_text
            assert test_ptr in result.stdout_text

            # Restart named and verify zone loads
            tasks.restart_named(self.master)
            time.sleep(5)

            # Check logs that zone was loaded without errors
            result = self.master.run_command([
                'journalctl', '-u', 'named', '-n', '100', '--no-pager'
            ])
            # Verify zone is mentioned in logs (loaded)
            assert reverse_zone in result.stdout_text, \
                f'Zone {reverse_zone} not found in named logs'

        finally:
            tasks.del_dns_zone(self.master, reverse_zone, raiseonerr=False)

    def test_tld_with_numbers(self):
        """Test DNS record allows top-level domains with numbers.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=907913

        Verify that DNS zones and records can be created with TLDs
        that contain numbers, and NS records can reference them.
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        test_zone = "TBADTEST0"  # TLD with number
        test_record = "TBADTEST"

        try:
            # Add zone with numeric TLD
            tasks.add_dns_zone(
                self.master, test_zone,
                admin_email=f"hostmaster.{test_zone}"
            )

            # Add A record in the zone
            tasks.add_dns_record(
                self.master, test_zone, test_record, 'a', ['1.2.3.4']
            )

            self.master.run_command(['ipactl', 'restart'])

            # Verify NS hostname with numeric TLD is valid
            result = tasks.add_dns_record(
                self.master, domain, test_record, 'ns',
                [f'{test_record}.{test_zone}.']
            )
            assert result.returncode == 0

            # Cleanup NS record
            tasks.del_dns_record(
                self.master, domain, test_record,
                record_type='ns',
                record_value=[f'{test_record}.{test_zone}.']
            )

        finally:
            tasks.del_dns_zone(self.master, test_zone, raiseonerr=False)

    def test_rfc2317_classless_arpa(self):
        """Test dnszone-add supports RFC 2317 classless in-addr.arpa.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1058688

        Verify that DNS zones with RFC 2317 classless reverse delegation
        format (like 0/27.10.10.in-addr.arpa) can be created.
        """
        tasks.kinit_admin(self.master)
        # RFC 2317 classless delegation format
        test_zone = "0/27.10.10.in-addr.arpa."

        try:
            # Add zone with RFC 2317 format
            tasks.add_dns_zone(
                self.master, test_zone,
                skip_overlap_check=True,
                admin_email="hostmaster.0.0.10.10.in-addr.arpa."
            )

            # Verify zone was created
            result = tasks.find_dns_zone(self.master, test_zone)
            assert result.returncode == 0
            assert test_zone in result.stdout_text

        finally:
            tasks.del_dns_zone(self.master, test_zone, raiseonerr=False)

    def test_dnsrecord_mod_no_warning(self):
        """Test dnsrecord-mod doesn't display API version warning.

        Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1054869

        Verify that modifying DNS records doesn't show warning message
        about API version. Also tests that setting txt-rec to empty
        deletes the record.
        """
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name
        record_name = "bz1054869"

        try:
            # Add TXT record
            tasks.add_dns_record(
                self.master, domain, record_name, 'txt', ['1054869']
            )

            # Verify record was added
            result = tasks.show_dns_record(
                self.master, domain, record_name, '--all', '--raw'
            )
            assert 'txtrecord: 1054869' in result.stdout_text.lower()

            # Modify record with empty txt-rec (deletes the record)
            result = tasks.mod_dns_record(
                self.master, domain, record_name,
                '--txt-rec='
            )
            # Verify no API version warning
            assert 'WARNING: API Version' not in result.stdout_text

            # Verify record was deleted
            result = tasks.find_dns_record(
                self.master, domain, record_name, raiseonerr=False
            )
            assert result.returncode != 0

        finally:
            tasks.del_dns_record(
                self.master, domain, record_name,
                del_all=True, raiseonerr=False
            )

    def test_dnszone_disable_enable_and_system_records(self):
        """Test dnszone-disable, dnszone-enable and dns-update-system-records.

        This test verifies that:
        1. A DNS zone can be disabled and enabled
        2. dns-update-system-records works correctly (dry-run and actual)
        """
        tasks.kinit_admin(self.master)
        test_zone = 'disabletest.test'

        try:
            # Add test zone
            tasks.add_dns_zone(
                self.master, test_zone,
                admin_email=f'hostmaster.{test_zone}'
            )

            result = self.master.run_command([
                'ipa', 'dnszone-show', test_zone
            ])
            assert 'Active zone: True' in result.stdout_text

            # Disable the zone
            result = self.master.run_command([
                'ipa', 'dnszone-disable', test_zone
            ])
            assert f'Disabled DNS zone "{test_zone}."' in result.stdout_text

            result = self.master.run_command([
                'ipa', 'dnszone-show', test_zone
            ])
            assert 'Active zone: False' in result.stdout_text

            # Enable the zone
            result = self.master.run_command([
                'ipa', 'dnszone-enable', test_zone
            ])
            assert f'Enabled DNS zone "{test_zone}."' in result.stdout_text

            result = self.master.run_command([
                'ipa', 'dnszone-show', test_zone
            ])
            assert 'Active zone: True' in result.stdout_text

            # Test dns-update-system-records --dry-run
            result = self.master.run_command([
                'ipa', 'dns-update-system-records', '--dry-run'
            ])
            assert result.returncode == 0

            result = self.master.run_command([
                'ipa', 'dns-update-system-records'
            ])
            assert result.returncode == 0

        finally:
            tasks.del_dns_zone(self.master, test_zone, raiseonerr=False)
