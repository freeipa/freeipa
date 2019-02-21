#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""
Test certificate requests with IP addresses in SAN, and error
scenarios.

Tests use the default profile (caIPAserviceCert) and the main CA.
The operator is ``admin``.

Various DNS records are created, modified and deleted during this
test.

"""

import ipaddress
import pytest

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ipalib import api, errors
from ipatests.test_util import yield_fixture
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test

host_fqdn = 'iptest.{}'.format(api.env.domain)
host_princ = 'host/{}'.format(host_fqdn)
host_ptr = '{}.'.format(host_fqdn)

other_fqdn = 'other.{}'.format(api.env.domain)
other_ptr = '{}.'.format(other_fqdn)

ipv4_address = '169.254.0.42'
ipv4_revzone_s = '0.254.169.in-addr.arpa.'
ipv4_revrec_s = '42'

ipv6_address = 'fe80::8f18:bdab:4299:95fa'
ipv6_revzone_s = '0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.'
ipv6_revrec_s = 'a.f.5.9.9.9.2.4.b.a.d.b.8.1.f.8'


@pytest.fixture(scope='class')
def host(request):
    tr = HostTracker('iptest')
    return tr.make_fixture(request)


def _zone_setup(host, zone):
    try:
        host.run_command('dnszone_add', zone)
    except errors.DuplicateEntry:
        delete = False
    else:
        delete = True

    yield zone

    if delete:
        host.run_command('dnszone_del', zone)


def _record_setup(host, zone, record, **kwargs):
    try:
        host.run_command('dnsrecord_add', zone, record, **kwargs)
    except (errors.DuplicateEntry, errors.EmptyModlist):
        delete = False
    else:
        delete = True

    yield

    if delete:
        host.run_command('dnsrecord_del', zone, record, **kwargs)


@yield_fixture(scope='class')
def ipv4_revzone(host):
    for x in _zone_setup(host, ipv4_revzone_s):
        yield x


@yield_fixture(scope='class')
def ipv6_revzone(host):
    for x in _zone_setup(host, ipv6_revzone_s):
        yield x


@yield_fixture(scope='class')
def ipv4_ptr(host, ipv4_revzone):
    for x in _record_setup(
            host, ipv4_revzone, ipv4_revrec_s, ptrrecord=host_ptr):
        yield x


@yield_fixture(scope='class')
def ipv6_ptr(host, ipv6_revzone):
    for x in _record_setup(
            host, ipv6_revzone, ipv6_revrec_s, ptrrecord=host_ptr):
        yield x


@yield_fixture(scope='class')
def ipv4_a(host):
    for x in _record_setup(
            host, api.env.domain, 'iptest', arecord=ipv4_address):
        yield x


@yield_fixture(scope='class')
def ipv6_aaaa(host):
    for x in _record_setup(
            host, api.env.domain, 'iptest', aaaarecord=ipv6_address):
        yield x


@yield_fixture(scope='class')
def other_forward_records(host):
    """
    Create A and AAAA records (to the "correct" IP address) for
    the name "other.{domain}.".

    """
    for x in _record_setup(
            host, api.env.domain, 'other',
            arecord=ipv4_address, aaaarecord=ipv6_address):
        yield x


@yield_fixture(scope='function')
def ipv4_ptr_other(host, ipv4_revzone):
    for x in _record_setup(
            host, ipv4_revzone, ipv4_revrec_s, ptrrecord=other_ptr):
        yield x


@yield_fixture(scope='class')
def cname1(host):
    for x in _record_setup(
            host, api.env.domain, 'cname1', cnamerecord='iptest'):
        yield x


@yield_fixture(scope='class')
def cname2(host):
    for x in _record_setup(
            host, api.env.domain, 'cname2', cnamerecord='cname1'):
        yield x


@pytest.fixture(scope='module')
def private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def csr(altnames, cn=host_fqdn):
    """
    Return a fixture that generates a CSR with the given altnames.
    The altname values MUST be of type x509.DNSName, x509.IPAddress, etc.

    The subject DN is always to CN={host_fqdn}.

    """
    def inner(private_key):
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        if len(altnames) > 0:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(altnames), False)
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        return csr.public_bytes(serialization.Encoding.PEM).decode('ascii')

    return pytest.fixture(scope='module')(inner)


csr_ipv4 = csr([
    x509.DNSName(host_fqdn),
    x509.IPAddress(ipaddress.ip_address(ipv4_address)),
])
csr_ipv6 = csr([
    x509.DNSName(host_fqdn),
    x509.IPAddress(ipaddress.ip_address(ipv6_address)),
])
csr_ipv4_ipv6 = csr([
    x509.DNSName(host_fqdn),
    x509.IPAddress(ipaddress.ip_address(ipv4_address)),
    x509.IPAddress(ipaddress.ip_address(ipv6_address)),
])
csr_extra_ipv4 = csr([
    x509.DNSName(host_fqdn),
    x509.IPAddress(ipaddress.ip_address(ipv4_address)),
    x509.IPAddress(ipaddress.ip_address('172.16.254.254')),
])
csr_no_dnsname = csr([
    x509.IPAddress(ipaddress.ip_address(ipv4_address)),
])
csr_alice = csr([
    x509.DNSName(host_fqdn),
    x509.IPAddress(ipaddress.ip_address(ipv4_address)),
], cn='alice')
csr_iptest_other = csr([
    x509.DNSName(host_fqdn),
    x509.DNSName(other_fqdn),
    x509.IPAddress(ipaddress.ip_address(ipv4_address)),
])
csr_cname1 = csr([
    x509.DNSName('cname1.{}'.format(api.env.domain)),
    x509.IPAddress(ipaddress.ip_address(ipv4_address)),
])
csr_cname2 = csr([
    x509.DNSName('cname2.{}'.format(api.env.domain)),
    x509.IPAddress(ipaddress.ip_address(ipv4_address)),
])


@pytest.fixture
def user_alice(request):
    user = UserTracker('alice', 'Alice', 'Able')
    return user.make_fixture(request)


@pytest.mark.tier1
class TestIPAddressSANIssuance(XMLRPC_test):
    """
    These are the tests that can be executed using the "correct" DNS
    records.  Tests for failure scenarios that require "incorrect"
    records are found in other classes.

    """
    def test_host_exists(self, host):
        host.ensure_exists()

    def test_issuance_ipv4(self, host, ipv4_a, ipv4_ptr, csr_ipv4):
        host.run_command('cert_request', csr_ipv4, principal=host_princ)

    def test_issuance_ipv6(self, host, ipv6_aaaa, ipv6_ptr, csr_ipv6):
        host.run_command('cert_request', csr_ipv6, principal=host_princ)

    def test_issuance_ipv4_ipv6(
            self, host, ipv4_a, ipv6_aaaa, ipv4_ptr, ipv6_ptr, csr_ipv4_ipv6):
        host.run_command('cert_request', csr_ipv4_ipv6, principal=host_princ)

    def test_failure_extra_ip(self, host, ipv4_a, ipv4_ptr, csr_extra_ipv4):
        with pytest.raises(errors.ValidationError):
            host.run_command(
                'cert_request', csr_extra_ipv4, principal=host_princ)

    def test_failure_no_dnsname(self, host, ipv4_a, ipv4_ptr, csr_no_dnsname):
        with pytest.raises(errors.ValidationError):
            host.run_command(
                'cert_request', csr_no_dnsname, principal=host_princ)

    def test_failure_user_princ(
            self, host, ipv4_a, ipv4_ptr, csr_alice, user_alice):
        user_alice.ensure_exists()
        with pytest.raises(errors.ValidationError):
            host.run_command(
                'cert_request', csr_alice, principal=user_alice.uid)


@pytest.mark.tier1
class TestIPAddressSANMissingARecord(XMLRPC_test):
    """When there is no A record for the DNS name."""
    def test_host_exists(self, host):
        host.ensure_exists()

    def test_issuance_ipv4(
            self, host, ipv6_aaaa, ipv6_ptr, ipv4_ptr, csr_ipv4):
        """Issuing with IPv4 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command('cert_request', csr_ipv4, principal=host_princ)

    def test_issuance_ipv6(
            self, host, ipv6_aaaa, ipv6_ptr, ipv4_ptr, csr_ipv6):
        """Issuing with IPv6 address succeeds."""
        host.run_command('cert_request', csr_ipv6, principal=host_princ)

    def test_issuance_ipv4_ipv6(
            self, host, ipv6_aaaa, ipv4_ptr, ipv6_ptr, csr_ipv4_ipv6):
        """Issuing with IPv4 *and* IPv6 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command(
                'cert_request', csr_ipv4_ipv6, principal=host_princ)


@pytest.mark.tier1
class TestIPAddressSANMissingAAAARecord(XMLRPC_test):
    """When there is no AAAA record for the DNS name."""
    def test_host_exists(self, host):
        host.ensure_exists()

    def test_issuance_ipv4(
            self, host, ipv4_a, ipv6_ptr, ipv4_ptr, csr_ipv4):
        """Issuing with IPv4 address suceeds."""
        host.run_command('cert_request', csr_ipv4, principal=host_princ)

    def test_issuance_ipv6(
            self, host, ipv4_a, ipv6_ptr, ipv4_ptr, csr_ipv6):
        """Issuing with IPv6 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command('cert_request', csr_ipv6, principal=host_princ)

    def test_issuance_ipv4_ipv6(
            self, host, ipv4_a, ipv4_ptr, ipv6_ptr, csr_ipv4_ipv6):
        """Issuing with IPv4 *and* IPv6 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command(
                'cert_request', csr_ipv4_ipv6, principal=host_princ)


@pytest.mark.tier1
class TestIPAddressSANMissingIPv4Ptr(XMLRPC_test):
    """When there is no IPv4 PTR record for the address."""
    def test_host_exists(self, host):
        host.ensure_exists()

    def test_issuance_ipv4(
            self, host, ipv4_a, ipv6_aaaa, ipv6_ptr, csr_ipv4):
        """Issuing with IPv4 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command('cert_request', csr_ipv4, principal=host_princ)

    def test_issuance_ipv6(
            self, host, ipv4_a, ipv6_aaaa, ipv6_ptr, csr_ipv6):
        """Issuing with IPv6 address succeeds."""
        host.run_command('cert_request', csr_ipv6, principal=host_princ)

    def test_issuance_ipv4_ipv6(
            self, host, ipv4_a, ipv6_aaaa, ipv6_ptr, csr_ipv4_ipv6):
        """Issuing with IPv4 *and* IPv6 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command(
                'cert_request', csr_ipv4_ipv6, principal=host_princ)


@pytest.mark.tier1
class TestIPAddressSANMissingIPv6Ptr(XMLRPC_test):
    """When there is no IPv6 PTR record for the address."""
    def test_host_exists(self, host):
        host.ensure_exists()

    def test_issuance_ipv4(
            self, host, ipv4_a, ipv6_aaaa, ipv4_ptr, csr_ipv4):
        """Issuing with IPv4 address succeeds."""
        host.run_command('cert_request', csr_ipv4, principal=host_princ)

    def test_issuance_ipv6(
            self, host, ipv4_a, ipv6_aaaa, ipv4_ptr, csr_ipv6):
        """Issuing with IPv6 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command('cert_request', csr_ipv6, principal=host_princ)

    def test_issuance_ipv4_ipv6(
            self, host, ipv4_a, ipv6_aaaa, ipv4_ptr, csr_ipv4_ipv6):
        """Issuing with IPv4 *and* IPv6 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command(
                'cert_request', csr_ipv4_ipv6, principal=host_princ)


@pytest.mark.tier1
class TestIPAddressSANOtherForwardRecords(XMLRPC_test):
    """
    A sanity check that we really are only looking at the
    forward records of interest.  We leave out records for
    the DNS name of interest, but create A and AAAA records
    for a different name in the same zone, which point to the
    IP address of interest.  Issuance must fail.

    """
    def test_host_exists(self, host):
        host.ensure_exists()

    def test_issuance_ipv4(
            self, host, other_forward_records, ipv4_ptr, ipv6_ptr, csr_ipv4):
        """Issuing with IPv4 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command('cert_request', csr_ipv4, principal=host_princ)

    def test_issuance_ipv6(
            self, host, other_forward_records, ipv4_ptr, ipv6_ptr, csr_ipv6):
        """Issuing with IPv6 address fails."""
        with pytest.raises(errors.ValidationError):
            host.run_command('cert_request', csr_ipv6, principal=host_princ)


@pytest.mark.tier1
class TestIPAddressPTRLoopback(XMLRPC_test):
    """
    A PTR record must point back to the name from which the IP
    address was reached.  Even when the PTR points to a name in the
    SAN, unless the aforementioned condition is satisfied, issuance
    must not proceed.

    ORDER IS IMPORTANT for this test (because the ipv4_ptr fixture
    has *class* scope).

    """
    def test_host_exists(self, host):
        host.ensure_exists()
        host.run_command(
            'host_add_principal', host.fqdn,
            'host/other.{}'.format(api.env.domain))

    def test_failure(self, host, ipv4_a, ipv4_ptr_other, csr_iptest_other):
        """The A and PTR records are not symmetric."""
        with pytest.raises(errors.ValidationError):
            host.run_command(
                'cert_request', csr_iptest_other, principal=host_princ)

    def test_success(self, host, ipv4_a, ipv4_ptr, csr_iptest_other):
        """
        The A and PTR records are symmetric.  This test ensures that the
        presence of an extra DNSName does not interfere with the IP address
        validation.

        """
        host.run_command(
            'cert_request', csr_iptest_other, principal=host_princ)


@pytest.mark.tier1
class TestIPAddressCNAME(XMLRPC_test):
    """
    A single level of CNAME indirection is supported.  PTR must be
    symmetric with the *canonical* name.

    Relevant principal aliases or managedby relationships are
    required by the DNSName validation regime.

    """
    def test_host_exists(self, host, cname1, cname2, ipv4_a, ipv4_ptr):
        # for convenience, this test also establishes the DNS
        # record fixtures, which have class scope
        host.ensure_exists()
        host.run_command(
            'host_add_principal', host.fqdn,
            'host/cname1.{}'.format(api.env.domain))
        host.run_command(
            'host_add_principal', host.fqdn,
            'host/cname2.{}'.format(api.env.domain))

    def test_one_level(self, host, csr_cname1):
        host.run_command('cert_request', csr_cname1, principal=host_princ)

    def test_two_levels(self, host, csr_cname2):
        with pytest.raises(errors.ValidationError):
            host.run_command('cert_request', csr_cname2, principal=host_princ)
