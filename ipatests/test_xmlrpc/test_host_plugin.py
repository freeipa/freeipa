# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2008, 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Test the `ipalib.plugins.host` module.
"""
from __future__ import print_function, absolute_import

import base64
import os
import tempfile

import pytest

from ipalib import api, errors, messages
from ipalib.constants import MAXHOSTNAMELEN
from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipatests.test_util import yield_fixture
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.test_user_plugin import get_group_dn
from ipatests.test_xmlrpc.testcert import get_testcert, subject_base
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipatests.test_xmlrpc.xmlrpc_test import (XMLRPC_test,
                                              fuzzy_uuid, fuzzy_digits,
                                              fuzzy_hash, fuzzy_date,
                                              fuzzy_issuer,
                                              fuzzy_hex, raises_exact)
from ipatests.util import assert_deepequal

# Constants DNS integration tests
# TODO: Use tracker fixtures for zones/records/users/groups
dnszone = u'test-zone.test'
dnszone_absolute = dnszone + '.'
dnszone_dn = DN(('idnsname', dnszone_absolute), api.env.container_dns, api.env.basedn)
dnszone_rname = u'root.%s' % dnszone_absolute
dnszone_rname_dnsname = DNSName(dnszone_rname)

revzone = u'29.16.172.in-addr.arpa.'
revzone_dn = DN(('idnsname', revzone), api.env.container_dns, api.env.basedn)

revipv6zone = u'0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
revipv6zone_dn = DN(('idnsname', revipv6zone), api.env.container_dns, api.env.basedn)

arec = u'172.16.29.22'
aaaarec = u'2001:db8:1::beef'

arec2 = u'172.16.29.33'
aaaarec2 = u'2001:db8:1::dead'

ipv4_fromip = u'testipv4fromip'
ipv4_fromip_ip = u'172.16.29.40'
ipv4_fromip_arec = ipv4_fromip_ip
ipv4_fromip_dnsname = DNSName(ipv4_fromip)
ipv4_fromip_dn = DN(('idnsname', ipv4_fromip), dnszone_dn)
ipv4_fromip_host_fqdn = u'%s.%s' % (ipv4_fromip, dnszone)
ipv4_fromip_ptr = u'40'
ipv4_fromip_ptr_dnsname = DNSName(ipv4_fromip_ptr)
ipv4_fromip_ptr_dn = DN(('idnsname', ipv4_fromip_ptr), revzone_dn)

ipv6_fromip = u'testipv6fromip'
ipv6_fromip_ipv6 = u'2001:db8:1::9'
ipv6_fromip_aaaarec = ipv6_fromip_ipv6
ipv6_fromip_dnsname = DNSName(ipv6_fromip)
ipv6_fromip_dn = DN(('idnsname', ipv6_fromip), dnszone_dn)
ipv6_fromip_ptr = u'9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0'
ipv6_fromip_ptr_dnsname = DNSName(ipv6_fromip_ptr)
ipv6_fromip_ptr_dn = DN(('idnsname', ipv6_fromip_ptr), revipv6zone_dn)

sshpubkey = u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGAX3xAeLeaJggwTqMjxNwa6XHBUAikXPGMzEpVrlLDCZtv00djsFTBi38PkgxBJVkgRWMrcBsr/35lq7P6w8KGIwA8GI48Z0qBS2NBMJ2u9WQ2hjLN6GdMlo77O0uJY3251p12pCVIS/bHRSq8kHO2No8g7KA9fGGcagPfQH+ee3t7HUkpbQkFTmbPPN++r3V8oVUk5LxbryB3UIIVzNmcSIn3JrXynlvui4MixvrtX6zx+O/bBo68o8/eZD26QrahVbA09fivrn/4h3TM019Eu/c2jOdckfU3cHUV/3Tno5d6JicibyaoDDK7S/yjdn5jhaz8MSEayQvFkZkiF0L public key test'
sshpubkeyfp = u'SHA256:cStA9o5TRSARbeketEOooMUMSWRSsArIAXloBZ4vNsE public key test (ssh-rsa)'

user1 = u'tuser1'
user2 = u'tuser2'
group1 = u'group1'
group1_dn = get_group_dn(group1)
group2 = u'group2'
group2_dn = get_group_dn(group2)
hostgroup1 = u'testhostgroup1'
hostgroup1_dn = DN(('cn',hostgroup1),('cn','hostgroups'),('cn','accounts'),
                   api.env.basedn)

host_cert = get_testcert(DN(('CN', api.env.host), subject_base()),
                         'host/%s@%s' % (api.env.host, api.env.realm))

missingrevzone = u'22.30.16.172.in-addr.arpa.'
ipv4_in_missingrevzone_ip = u'172.16.30.22'


@pytest.fixture(scope='class')
def host(request, xmlrpc_setup):
    tracker = HostTracker(name=u'testhost1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host2(request, xmlrpc_setup):
    tracker = HostTracker(name=u'testhost2')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host3(request, xmlrpc_setup):
    tracker = HostTracker(name=u'testhost3')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host4(request, xmlrpc_setup):
    tracker = HostTracker(name=u'testhost4')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host5(request, xmlrpc_setup):
    tracker = HostTracker(name=u'testhost5')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def lab_host(request, xmlrpc_setup):
    name = u'testhost1'
    tracker = HostTracker(name=name,
                          fqdn=u'%s.lab.%s' % (name, api.env.domain))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def this_host(request, xmlrpc_setup):
    """Fixture for the current master"""
    tracker = HostTracker(name=api.env.host.partition('.')[0],
                          fqdn=api.env.host)
    tracker.exists = True
    # Finalizer ensures that any certificates added to this_host are removed
    tracker.add_finalizer_certcleanup(request)
    # This host is not created/deleted, so don't call make_fixture
    return tracker


@pytest.fixture(scope='class')
def invalid_host(request, xmlrpc_setup):
    tracker = HostTracker(name='foo_bar',)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv6only_host(request, xmlrpc_setup):
    name = u'testipv6onlyhost'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv4only_host(request, xmlrpc_setup):
    name = u'testipv4onlyhost'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv46both_host(request, xmlrpc_setup):
    name = u'testipv4and6host'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv4_fromip_host(request, xmlrpc_setup):
    name = u'testipv4fromip'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv6_fromip_host(request, xmlrpc_setup):
    name = u'testipv6fromip'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestNonexistentHost(XMLRPC_test):
    def test_retrieve_nonexistent(self, host):
        host.ensure_missing()
        command = host.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % host.fqdn)):
            command()

    def test_update_nonexistent(self, host):
        host.ensure_missing()
        command = host.make_update_command(updates=dict(description=u'Nope'))
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % host.fqdn)):
            command()

    def test_delete_nonexistent(self, host):
        host.ensure_missing()
        command = host.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % host.fqdn)):
            command()


@pytest.mark.tier1
class TestCRUD(XMLRPC_test):
    def test_create_duplicate(self, host):
        host.ensure_exists()
        command = host.make_create_command(force=True)
        with raises_exact(errors.DuplicateEntry(
                message=u'host with name "%s" already exists' % host.fqdn)):
            command()

    def test_retrieve_simple(self, host):
        host.retrieve()

    def test_retrieve_all(self, host):
        host.retrieve(all=True)

    def test_search_simple(self, host):
        host.find()

    def test_search_all(self, host):
        host.find(all=True)

    def test_update_simple(self, host):
        host.update(dict(
            description=u'Updated host 1',
            usercertificate=host_cert),
            expected_updates=dict(
                description=[u'Updated host 1'],
                usercertificate=[base64.b64decode(host_cert)],
                issuer=fuzzy_issuer,
                serial_number=fuzzy_digits,
                serial_number_hex=fuzzy_hex,
                sha1_fingerprint=fuzzy_hash,
                sha256_fingerprint=fuzzy_hash,
                subject=DN(('CN', api.env.host), subject_base()),
                valid_not_before=fuzzy_date,
                valid_not_after=fuzzy_date,
        )
        )
        host.retrieve()
        # test host-find with --certificate
        command = host.make_find_command(
            fqdn=host.fqdn, usercertificate=host_cert)
        res = command()['result']
        assert len(res) == 1

    def test_host_find_pkey_only(self, host5):
        # test host-find with --pkey-only
        host5.ensure_exists()
        command = host5.make_create_command(force=True)
        host5.update(dict(ipasshpubkey=sshpubkey),
                     expected_updates=dict(
                         description=['Test host <testhost5>'],
                         fqdn=[host5.fqdn],
                         ipasshpubkey=[sshpubkey],
                         has_keytab=False,
                         has_password=False,
                         krbprincipalname=['host/%s@%s' %
                                           (host5.fqdn, api.env.realm)],
                         krbcanonicalname=['host/%s@%s' %
                                           (host5.fqdn, api.env.realm)],
                         managedby_host=[host5.fqdn],
                         sshpubkeyfp=[sshpubkeyfp], ))
        command = host5.make_find_command(
            fqdn=host5.fqdn, pkey_only=True)
        result = command()['result']
        for item in result:
            assert 'ipasshpubkey' not in item.keys()

    def test_try_rename(self, host):
        host.ensure_exists()
        command = host.make_update_command(
            updates=dict(setattr=u'fqdn=changed.example.com'))
        with raises_exact(errors.NotAllowedOnRDN()):
            command()

    def test_add_mac_address(self, host):
        host.update(dict(macaddress=u'00:50:56:30:F6:5F'),
                    expected_updates=dict(macaddress=[u'00:50:56:30:F6:5F']))
        host.retrieve()

    def test_add_mac_addresses(self, host):
        host.update(dict(macaddress=[u'00:50:56:30:F6:5F',
                                     u'00:50:56:2C:8D:82']))
        host.retrieve()

    def test_try_illegal_mac(self, host):
        command = host.make_update_command(
            updates=dict(macaddress=[u'xx']))
        with raises_exact(errors.ValidationError(
                name='macaddress',
                error=u'Must be of the form HH:HH:HH:HH:HH:HH, where ' +
                      u'each H is a hexadecimal character.')):
            command()

    def test_add_ssh_pubkey(self, host):
        host.update(dict(ipasshpubkey=[sshpubkey]),
                    expected_updates=dict(
                        ipasshpubkey=[sshpubkey],
                        sshpubkeyfp=[sshpubkeyfp],
                    ))
        host.retrieve()

    def test_try_illegal_ssh_pubkey(self, host):
        host.ensure_exists()
        command = host.make_update_command(
            updates=dict(ipasshpubkey=[u'no-pty %s' % sshpubkey]))
        with raises_exact(errors.ValidationError(
                name='sshpubkey', error=u'options are not allowed')):
            command()

    def test_delete_host(self, host):
        host.delete()

    def test_retrieve_nonexistent(self, host):
        host.ensure_missing()
        command = host.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % host.fqdn)):
            command()

    def test_update_nonexistent(self, host):
        host.ensure_missing()
        command = host.make_update_command(
            updates=dict(description=u'Nope'))
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % host.fqdn)):
            command()

    def test_delete_nonexistent(self, host):
        host.ensure_missing()
        command = host.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % host.fqdn)):
            command()

    def test_try_add_not_in_dns(self, host):
        host.ensure_missing()
        command = host.make_create_command(force=False)
        with raises_exact(errors.DNSNotARecordError(hostname=host.fqdn)):
            command()

    def test_add_host_with_null_password(self, host):
        host.ensure_missing()
        command = host.make_create_command()
        result = command(userpassword=None)
        host.track_create()
        host.check_create(result)

    @staticmethod
    def modify_config_maxhostname(host_tracker, value):
        try:
            command = host_tracker.make_command(
                'config_mod',
                **dict(
                    setattr=u'ipamaxhostnamelength={}'.format(value)))
            command()
        except errors.EmptyModlist:
            pass

    @staticmethod
    def generate_hostname(total_length, label_len=5):
        """Helper function to generate hostname given total length and
        optional DNS label length
        :param total_length: total length of fqdn
        :param label_len: label length
        :return: fqdn like string
        """
        if total_length < 9:
            raise ArithmeticError("Total DNS length in theses tests"
                                  "must be at least 9")
        no_of_labels = total_length // (label_len + 1)
        remainder = total_length % (label_len + 1)
        return '{}{}{}'.format(
            (no_of_labels - 1) * '{}.'.format(label_len * 'a'),
            label_len * 'b' if remainder != 0 else (label_len + 1) * 'b',
            ".{}".format(remainder * 'c') if remainder != 0 else "")

    def test_config_maxhostname_invalid(self, host):
        """Change config maxhostname to an invalid value
        (lower than MAXHOSTNAMELEN). Should fail"""
        with raises_exact(errors.ValidationError(
                name='ipamaxhostnamelength',
                error='must be at least {}'.format(MAXHOSTNAMELEN))):
            self.modify_config_maxhostname(host, MAXHOSTNAMELEN // 2)

    def test_raise_hostname_limit_above_maxhostnamelen(self, host):
        """Raise config maxhostname to a value above the default
        (MAXHOSTNAMELEN). Should pass"""
        self.modify_config_maxhostname(host, MAXHOSTNAMELEN * 2)

    def test_try_hostname_length_above_maxhostnamelimit(self):
        """Try to create host with hostname length above
        hostnamelength limit. Should fail"""
        testhost = HostTracker(name=u'testhost',
                               fqdn=u'{}'.format(
                                   self.generate_hostname(MAXHOSTNAMELEN + 1)))
        self.modify_config_maxhostname(testhost, MAXHOSTNAMELEN)
        with raises_exact(errors.ValidationError(
                name=u'hostname',
                error=u'can be at most {} characters'.format(
                    MAXHOSTNAMELEN))):
            testhost.create()
            testhost.ensure_missing()

    def test_try_hostname_length_below_maximum(self):
        """Try to create host with valid hostname. Should pass"""
        valid_length = MAXHOSTNAMELEN // 2
        testhost = HostTracker(name=u'testhost',
                               fqdn=u'{}'.format(
                                   self.generate_hostname(valid_length)))
        self.modify_config_maxhostname(testhost, MAXHOSTNAMELEN)
        testhost.create()
        testhost.ensure_missing()

    def test_raise_limit_above_and_try_hostname_len_above_limit(self):
        """Raise limit above default and try to create host with hostname
        length above the new-set limit. Should fail"""
        testhost = HostTracker(name=u'testhost',
                               fqdn=u'{}'.format(
                                   self.generate_hostname(MAXHOSTNAMELEN * 3)))
        self.modify_config_maxhostname(testhost, MAXHOSTNAMELEN * 2)
        with raises_exact(errors.ValidationError(
                name='hostname',
                error=u'can be at most {} characters'.format(
                    MAXHOSTNAMELEN * 2))):
            testhost.create()
            testhost.ensure_missing()

    def test_raise_limit_and_try_valid_len_hostname(self):
        """Raise limit above default and test hostname with length
        in between default 64 and the new value. Should pass"""
        testhost = HostTracker(name=u'testhost',
                               fqdn=u'{}'.format(
                                   self.generate_hostname(MAXHOSTNAMELEN + 1)))
        self.modify_config_maxhostname(testhost, MAXHOSTNAMELEN * 2)
        testhost.create()
        testhost.ensure_missing()


@pytest.mark.tier1
class TestMultipleMatches(XMLRPC_test):
    def test_try_show_multiple_matches_with_shortname(self, host, lab_host):
        host.ensure_exists()
        lab_host.ensure_exists()
        assert host.shortname == lab_host.shortname
        command = host.make_command('host_show', host.shortname)
        with pytest.raises(errors.SingleMatchExpected):
            command()


@pytest.mark.tier1
class TestHostWithService(XMLRPC_test):
    """Test deletion using a non-fully-qualified hostname.
    Services associated with this host should also be removed.
    """

    # TODO: Use a service tracker, when available

    def test_host_with_service(self, host):
        host.ensure_exists()

        service1 = u'dns/%s@%s' % (host.fqdn, host.api.env.realm)
        service1dn = DN(('krbprincipalname', service1.lower()),
                        ('cn','services'), ('cn','accounts'),
                        host.api.env.basedn)

        try:
            result = host.run_command('service_add', service1, force=True)
            assert_deepequal(dict(
                value=service1,
                summary=u'Added service "%s"' % service1,
                result=dict(
                    dn=service1dn,
                    krbprincipalname=[service1],
                    krbcanonicalname=[service1],
                    objectclass=objectclasses.service,
                    managedby_host=[host.fqdn],
                    ipauniqueid=[fuzzy_uuid],
                ),
            ), result)

            host.delete()

            result = host.run_command('service_find', host.fqdn)
            assert_deepequal(dict(
                count=0,
                truncated=False,
                summary=u'0 services matched',
                result=[],
            ), result)
        finally:
            try:
                host.run_command('service_del', service1)
            except errors.NotFound:
                pass


@pytest.mark.tier1
class TestManagedHosts(XMLRPC_test):
    def test_managed_hosts(self, host, host2, host3):
        host.ensure_exists()
        host2.ensure_exists()
        host3.ensure_exists()

        self.add_managed_host(host, host2)
        host2.retrieve()

        self.search_man_noman_hosts(host2, host)
        self.search_man_hosts(host2, host3)

        self.remove_man_hosts(host, host2)
        host.retrieve()
        host2.retrieve()

    def add_managed_host(self, manager, underling):
        command = manager.make_command('host_add_managedby',
                                       underling.fqdn, host=manager.fqdn)
        result = command()
        underling.attrs['managedby_host'] = [manager.fqdn, underling.fqdn]

        assert_deepequal(dict(
            completed=1,
            failed={'managedby': {'host': ()}},
            result=underling.filter_attrs(underling.managedby_keys),
        ), result)

    def search_man_noman_hosts(self, host, noman_host):
        command = host.make_find_command(host.fqdn,
                                         man_host=host.fqdn,
                                         not_man_host=noman_host.fqdn)
        result = command()
        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 host matched',
            result=[host.filter_attrs(host.find_keys)],
        ), result)

    def search_man_hosts(self, host1, host2):
        command = host1.make_find_command(man_host=[host1.fqdn, host2.fqdn])
        result = command()
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary=u'0 hosts matched',
            result=[],
        ), result)

    def remove_man_hosts(self, manager, underling):
        command = manager.make_command('host_remove_managedby',
                                       underling.fqdn, host=manager.fqdn)
        result = command()

        underling.attrs['managedby_host'] = [underling.fqdn]

        assert_deepequal(dict(
            completed=1,
            failed={'managedby': {'host': ()}},
            result=underling.filter_attrs(underling.managedby_keys),
        ), result)


@pytest.mark.tier1
class TestProtectedMaster(XMLRPC_test):
    def test_try_delete_master(self, this_host):
        command = this_host.make_delete_command()
        with raises_exact(errors.ValidationError(
                name='hostname',
                error=u'An IPA master host cannot be deleted or disabled')):
            command()

    def test_try_disable_master(self, this_host):
        command = this_host.make_command('host_disable', this_host.fqdn)
        with raises_exact(errors.ValidationError(
                name='hostname',
                error=u'An IPA master host cannot be deleted or disabled')):
            command()


@pytest.mark.tier1
class TestValidation(XMLRPC_test):
    def test_try_validate_create(self, invalid_host):
        command = invalid_host.make_create_command()
        with raises_exact(errors.ValidationError(
                name='hostname',
                error=u"invalid domain-name: only letters, numbers, '-' are " +
                      u"allowed. DNS label may not start or end with '-'")):
            command()

    # The assumption on these next 4 tests is that if we don't get a
    # validation error then the request was processed normally.

    def test_try_validate_update(self, invalid_host):
        command = invalid_host.make_update_command({})
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % invalid_host.fqdn)):
            command()

    def test_try_validate_delete(self, invalid_host):
        command = invalid_host.make_delete_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % invalid_host.fqdn)):
            command()

    def test_try_validate_retrieve(self, invalid_host):
        command = invalid_host.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason=u'%s: host not found' % invalid_host.fqdn)):
            command()

    def test_try_validate_find(self, invalid_host):
        command = invalid_host.make_find_command(invalid_host.fqdn)
        result = command()
        assert_deepequal(dict(
            count=0,
            truncated=False,
            summary=u'0 hosts matched',
            result=[],
        ), result)


@yield_fixture
def keytabname(request):
    keytabfd, keytabname = tempfile.mkstemp()
    try:
        os.close(keytabfd)
        yield keytabname
    finally:
        os.unlink(keytabname)


@pytest.mark.tier1
class TestHostFalsePwdChange(XMLRPC_test):

    def test_join_host(self, host, keytabname):
        """
        Create a test host and join it into IPA.

        This test must not run remotely.
        """

        if not os.path.isfile(paths.SBIN_IPA_JOIN):
            pytest.skip("Command '%s' not found. "
                        "The test must not run remotely."
                        % paths.SBIN_IPA_JOIN)

        # create a test host with bulk enrollment password
        host.track_create()

        # manipulate host.attrs to correspond with real attributes of host
        # after creating it with random password
        del host.attrs['krbprincipalname']
        del host.attrs['krbcanonicalname']
        host.attrs['has_password'] = True
        objclass = list(set(
            host.attrs['objectclass']) - {u'krbprincipal', u'krbprincipalaux'})
        host.attrs['objectclass'] = objclass

        command = host.make_create_command(force=True)
        result = command(random=True)
        random_pass = result['result']['randompassword']

        host.attrs['randompassword'] = random_pass
        host.check_create(result)

        del host.attrs['randompassword']

        # joint the host with the bulk password
        new_args = [
            paths.SBIN_IPA_JOIN,
            "-s", host.api.env.host,
            "-h", host.fqdn,
            "-k", keytabname,
            "-w", random_pass,
            "-q",
        ]

        try:
            ipautil.run(new_args)
        except ipautil.CalledProcessError as e:
            # join operation may fail on 'adding key into keytab', but
            # the keytab is not necessary for further tests
            print(e)

        # fix host.attrs again to correspond with current state
        host.attrs['has_keytab'] = True
        host.attrs['has_password'] = False
        host.attrs['krbprincipalname'] = [u'host/%s@%s' % (host.fqdn,
                                                           host.api.env.realm)]
        host.attrs['krbcanonicalname'] = [u'host/%s@%s' % (host.fqdn,
                                                           host.api.env.realm)]
        host.retrieve()

        # Try to change the password of enrolled host with specified password
        command = host.make_update_command(
            updates=dict(userpassword=u'pass_123'))
        with pytest.raises(errors.ValidationError):
            command()

        # Try to change the password of enrolled host with random password
        command = host.make_update_command(updates=dict(random=True))
        with pytest.raises(errors.ValidationError):
            command()


@yield_fixture(scope='class')
def dns_setup_nonameserver(host4):
    # Make sure that the server does not handle the reverse zone used
    # for the test
    try:
        host4.run_command('dnszone_del', missingrevzone, **{'continue': True})
    except (errors.NotFound, errors.EmptyModlist):
        pass

    # Save the current forward policy
    result = host4.run_command('dnsserver_show', api.env.host)
    current_fwd_pol = result['result']['idnsforwardpolicy'][0]

    # Configure the forward policy to none to make sure that no DNS
    # server will answer for the reverse zone either
    try:
        host4.run_command('dnsserver_mod', api.env.host,
                          idnsforwardpolicy=u'none')
    except errors.EmptyModlist:
        pass

    try:
        yield
    finally:
        # Restore the previous forward-policy
        try:
            host4.run_command('dnsserver_mod', api.env.host,
                              idnsforwardpolicy=current_fwd_pol)
        except errors.EmptyModlist:
            pass


@pytest.mark.tier1
class TestHostNoNameserversForRevZone(XMLRPC_test):
    def test_create_host_with_ip(self, dns_setup_nonameserver, host4):
        """
        Regression test for ticket 7397

        Configure the master with forward-policy = none to make sure
        that no DNS server will answer for the reverse zone
        Try to add a new host with an IP address in the missing reverse
        zone.
        With issue 7397, a NoNameserver exception generates a Traceback in
        httpd error_log, and the command returns an InternalError.
        """
        try:
            command = host4.make_create_command()
            result = command(ip_address=ipv4_in_missingrevzone_ip)
            msg = result['messages'][0]
            assert msg['code'] == messages.FailedToAddHostDNSRecords.errno
            expected = "The host was added but the DNS update failed"
            # Either one of:
            # All nameservers failed to answer the query for DNS reverse zone
            # DNS reverse zone ... is not managed by this server
            assert expected in msg['message']
            # Make sure the host is added
            host4.run_command('host_show', host4.fqdn)
        finally:
            # Delete the host entry
            command = host4.make_delete_command()
            try:
                command(updatedns=True)
            except errors.NotFound:
                pass

    def test_create_host_with_otp(self, dns_setup_nonameserver, host4):
        """
        Create a test host specifying an IP address for which
        IPA does not handle the reverse zone, and requesting
        the creation of a random password.
        Non-reg test for ticket 7374.
        """

        command = host4.make_create_command()
        try:
            result = command(random=True, ip_address=ipv4_in_missingrevzone_ip)
            # Make sure a random password is returned
            assert result['result']['randompassword']
            # Make sure the warning about missing DNS record is added
            msg = result['messages'][0]
            assert msg['code'] == messages.FailedToAddHostDNSRecords.errno
            assert msg['message'].startswith(
                u'The host was added but the DNS update failed with:')
        finally:
            # Cleanup
            try:
                command = host4.make_delete_command()
                command(updatedns=True)
            except errors.NotFound:
                pass


@yield_fixture(scope='class')
def dns_setup(host):
    try:
        host.run_command('dnszone_del', dnszone, revzone, revipv6zone,
                         **{'continue': True})
    except (errors.NotFound, errors.EmptyModlist):
        pass

    try:
        host.run_command('dnszone_add', dnszone, idnssoarname=dnszone_rname)
        host.run_command('dnszone_add', revzone, idnssoarname=dnszone_rname)
        host.run_command('dnszone_add', revipv6zone,
                         idnssoarname=dnszone_rname)
        yield
    finally:
        try:
            host.run_command('dnszone_del', dnszone, revzone, revipv6zone,
                             **{'continue': True})
        except (errors.NotFound, errors.EmptyModlist):
            pass


@pytest.mark.tier1
class TestHostDNS(XMLRPC_test):
    def test_add_ipv6only_host(self, dns_setup, ipv6only_host):
        ipv6only_host.run_command('dnsrecord_add', dnszone,
                                  ipv6only_host.shortname, aaaarecord=aaaarec)
        try:
            ipv6only_host.create(force=False)
        finally:
            ipv6only_host.run_command(
                'dnsrecord_del', dnszone, ipv6only_host.shortname,
                aaaarecord=aaaarec)

    def test_add_ipv4only_host(self, dns_setup, ipv4only_host):
        ipv4only_host.run_command('dnsrecord_add', dnszone,
                                  ipv4only_host.shortname, arecord=arec)
        try:
            ipv4only_host.create(force=False)
        finally:
            ipv4only_host.run_command(
                'dnsrecord_del', dnszone, ipv4only_host.shortname,
                arecord=arec)

    def test_add_ipv46both_host(self, dns_setup, ipv46both_host):
        ipv46both_host.run_command('dnsrecord_add', dnszone,
                                   ipv46both_host.shortname,
                                   arecord=arec2, aaaarecord=aaaarec2)
        try:
            ipv46both_host.create(force=False)
        finally:
            ipv46both_host.run_command(
                'dnsrecord_del', dnszone, ipv46both_host.shortname,
                arecord=arec2, aaaarecord=aaaarec2)

    def test_add_ipv4_host_from_ip(self, dns_setup, ipv4_fromip_host):
        ipv4_fromip_host.ensure_missing()
        ipv4_fromip_host.track_create()
        command = ipv4_fromip_host.make_create_command(force=False)
        result = command(ip_address=ipv4_fromip_ip)
        ipv4_fromip_host.check_create(result)

        result = ipv4_fromip_host.run_command('dnsrecord_show', dnszone,
                                              ipv4_fromip_host.shortname)
        assert_deepequal(dict(
            value=ipv4_fromip_dnsname,
            summary=None,
            result=dict(
                dn=ipv4_fromip_dn,
                idnsname=[ipv4_fromip_dnsname],
                arecord=[ipv4_fromip_arec],
            ),
        ), result)

        result = ipv4_fromip_host.run_command('dnsrecord_show', revzone,
                                              ipv4_fromip_ptr)
        assert_deepequal(dict(
            value=ipv4_fromip_ptr_dnsname,
            summary=None,
            result=dict(
                dn=ipv4_fromip_ptr_dn,
                idnsname=[ipv4_fromip_ptr_dnsname],
                ptrrecord=[ipv4_fromip_host.fqdn + '.'],
            ),
        ), result)

    def test_add_ipv6_host_from_ip(self, dns_setup, ipv6_fromip_host):
        ipv6_fromip_host.ensure_missing()
        ipv6_fromip_host.track_create()
        command = ipv6_fromip_host.make_create_command(force=False)
        result = command(ip_address=ipv6_fromip_ipv6)
        ipv6_fromip_host.check_create(result)

        result = ipv6_fromip_host.run_command('dnsrecord_show', dnszone,
                                              ipv6_fromip_host.shortname)
        assert_deepequal(dict(
            value=ipv6_fromip_dnsname,
            summary=None,
            result=dict(
                dn=ipv6_fromip_dn,
                idnsname=[ipv6_fromip_dnsname],
                aaaarecord=[ipv6_fromip_aaaarec],
            ),
        ), result)

        result = ipv6_fromip_host.run_command('dnsrecord_show', revipv6zone,
                                              ipv6_fromip_ptr)
        assert_deepequal(dict(
            value=ipv6_fromip_ptr_dnsname,
            summary=None,
            result=dict(
                dn=ipv6_fromip_ptr_dn,
                idnsname=[ipv6_fromip_ptr_dnsname],
                ptrrecord=[ipv6_fromip_host.fqdn + '.'],
            ),
        ), result)


@pytest.fixture(scope='class')
def allowedto_context(request, host3):
    def cleanup():
        try:
            host3.run_command('user_del', user1, user2, **{'continue': True})
        except errors.NotFound:
            pass
        try:
            host3.run_command('group_del', group1, group2,
                              **{'continue': True})
        except errors.NotFound:
            pass
        try:
            host3.run_command('hostgroup_del', hostgroup1)
        except errors.NotFound:
            pass

    cleanup()
    request.addfinalizer(cleanup)

    host3.ensure_exists()

    host3.run_command('user_add', givenname=u'Test', sn=u'User1')
    host3.run_command('user_add', givenname=u'Test', sn=u'User2')
    host3.run_command('group_add', group1)
    host3.run_command('group_add', group2)
    host3.run_command('hostgroup_add', hostgroup1,
                      description=u'Test hostgroup 1')


@pytest.mark.tier1
class TestHostAllowedTo(XMLRPC_test):

    def test_user_allow_retrieve_keytab(self, allowedto_context, host):
        host.ensure_exists()
        result = host.run_command('host_allow_retrieve_keytab', host.fqdn,
                                  user=user1)
        host.attrs['ipaallowedtoperform_read_keys_user'] = [user1]
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[], host=[], hostgroup=[], user=[]),
            ),
            completed=1,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

        # Duplicates should not be accepted
        result = host.run_command('host_allow_retrieve_keytab', host.fqdn,
                                  user=user1)
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[], host=[], hostgroup=[],
                    user=[[user1, u'This entry is already a member']],
                ),
            ),
            completed=0,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

    def test_group_allow_retrieve_keytab(self, allowedto_context, host, host3):
        host.ensure_exists()
        host3.ensure_exists()
        result = host.run_command('host_allow_retrieve_keytab', host.fqdn,
                                  group=[group1, group2], host=[host3.fqdn],
                                  hostgroup=[hostgroup1])
        host.attrs['ipaallowedtoperform_read_keys_group'] = [group1, group2]
        host.attrs['ipaallowedtoperform_read_keys_host'] = [host3.fqdn]
        host.attrs['ipaallowedtoperform_read_keys_hostgroup'] = [hostgroup1]
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[], host=[], hostgroup=[], user=[]),
            ),
            completed=4,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

        # Non-members cannot be removed
        result = host.run_command('host_disallow_retrieve_keytab', host.fqdn,
                                  user=[user2])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[],
                    host=[],
                    hostgroup=[],
                    user=[[user2, u'This entry is not a member']],
                ),
            ),
            completed=0,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

        # Disallow one of the existing allowed groups
        result = host.run_command('host_disallow_retrieve_keytab', host.fqdn,
                                  group=[group2])
        host.attrs['ipaallowedtoperform_read_keys_group'] = [group1]
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_read_keys=dict(
                    group=[], host=[], hostgroup=[], user=[]),
            ),
            completed=1,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

        host.retrieve()

    def test_allow_create(self, allowedto_context, host, host3):
        host.ensure_exists()
        host3.ensure_exists()
        result = host.run_command('host_allow_create_keytab', host.fqdn,
                                  group=[group1, group2], user=[user1],
                                  host=[host3.fqdn],
                                  hostgroup=[hostgroup1])
        host.attrs['ipaallowedtoperform_write_keys_user'] = [user1]
        host.attrs['ipaallowedtoperform_write_keys_group'] = [group1, group2]
        host.attrs['ipaallowedtoperform_write_keys_host'] = [host3.fqdn]
        host.attrs['ipaallowedtoperform_write_keys_hostgroup'] = [hostgroup1]
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_write_keys=dict(
                    group=[], host=[], hostgroup=[], user=[]),
            ),
            completed=5,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

        # Duplicates should not be accepted
        result = host.run_command('host_allow_create_keytab', host.fqdn,
                                  group=[group1], user=[user1],
                                  host=[host3.fqdn], hostgroup=[hostgroup1])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_write_keys=dict(
                    group=[[group1, u'This entry is already a member']],
                    host=[[host3.fqdn, u'This entry is already a member']],
                    user=[[user1, u'This entry is already a member']],
                    hostgroup=[[hostgroup1,
                                u'This entry is already a member']],
                ),
            ),
            completed=0,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

        # Non-mambers cannot be removed
        result = host.run_command('host_disallow_create_keytab', host.fqdn,
                                  user=[user2])
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_write_keys=dict(
                    group=[],
                    host=[],
                    hostgroup=[],
                    user=[[user2, u'This entry is not a member']],
                ),
            ),
            completed=0,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

        # Disallow one of the existing allowed groups
        result = host.run_command('host_disallow_create_keytab', host.fqdn,
                                  group=[group2])
        host.attrs['ipaallowedtoperform_write_keys_group'] = [group1]
        assert_deepequal(dict(
            failed=dict(
                ipaallowedtoperform_write_keys=dict(
                    group=[],
                    host=[],
                    hostgroup=[],
                    user=[],
                ),
            ),
            completed=1,
            result=host.filter_attrs(host.allowedto_keys),
        ), result)

        host.retrieve()

    def test_host_mod(self, host):
        # Done (usually) at the end to ensure the tracking works well
        host.update(updates=dict(description=u'desc'),
                    expected_updates=dict(description=[u'desc']))
