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

import os
import tempfile
import base64

import pytest

from ipapython import ipautil
from ipalib import api, errors, x509
from ipapython.dn import DN
from ipapython.dnsutil import DNSName
from ipatests.test_xmlrpc.ldaptracker import Tracker
from ipatests.test_xmlrpc.xmlrpc_test import (XMLRPC_test,
    fuzzy_uuid, fuzzy_digits, fuzzy_hash, fuzzy_date, fuzzy_issuer,
    fuzzy_hex, raises_exact)
from ipatests.test_xmlrpc.test_user_plugin import get_group_dn
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.testcert import get_testcert
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
sshpubkeyfp = u'13:67:6B:BF:4E:A2:05:8E:AE:25:8B:A1:31:DE:6F:1B public key test (ssh-rsa)'

user1 = u'tuser1'
user2 = u'tuser2'
group1 = u'group1'
group1_dn = get_group_dn(group1)
group2 = u'group2'
group2_dn = get_group_dn(group2)
hostgroup1 = u'testhostgroup1'
hostgroup1_dn = DN(('cn',hostgroup1),('cn','hostgroups'),('cn','accounts'),
                    api.env.basedn)

host_cert = get_testcert(DN(('CN', api.env.host), x509.subject_base()),
                         'host/%s@%s' % (api.env.host, api.env.realm))


class HostTracker(Tracker):
    """Wraps and tracks modifications to a Host object

    Implements the helper functions for host plugin.

    The HostTracker object stores information about the host, e.g.
    ``fqdn`` and ``dn``.
    """
    retrieve_keys = {
        'dn', 'fqdn', 'description', 'l', 'krbprincipalname', 'managedby_host',
        'has_keytab', 'has_password', 'issuer', 'md5_fingerprint',
        'serial_number', 'serial_number_hex', 'sha1_fingerprint',
        'subject', 'usercertificate', 'valid_not_after', 'valid_not_before',
        'macaddress', 'sshpubkeyfp', 'ipaallowedtoperform_read_keys_user',
        'ipaallowedtoperform_read_keys_group',
        'ipaallowedtoperform_read_keys_host',
        'ipaallowedtoperform_read_keys_hostgroup',
        'ipaallowedtoperform_write_keys_user',
        'ipaallowedtoperform_write_keys_group',
        'ipaallowedtoperform_write_keys_host',
        'ipaallowedtoperform_write_keys_hostgroup'}
    retrieve_all_keys = retrieve_keys | {
        u'cn', u'ipakrbokasdelegate', u'ipakrbrequirespreauth', u'ipauniqueid',
        u'managing_host', u'objectclass', u'serverhostname'}
    create_keys = retrieve_keys | {'objectclass', 'ipauniqueid',
                                   'randompassword'}
    update_keys = retrieve_keys - {'dn'}
    managedby_keys = retrieve_keys - {'has_keytab', 'has_password'}
    allowedto_keys = retrieve_keys - {'has_keytab', 'has_password'}

    def __init__(self, name, fqdn=None, default_version=None):
        super(HostTracker, self).__init__(default_version=default_version)

        self.shortname = name
        if fqdn:
            self.fqdn = fqdn
        else:
            self.fqdn = u'%s.%s' % (name, self.api.env.domain)
        self.dn = DN(('fqdn', self.fqdn), 'cn=computers', 'cn=accounts',
                     self.api.env.basedn)

        self.description = u'Test host <%s>' % name
        self.location = u'Undisclosed location <%s>' % name

    def make_create_command(self, force=True):
        """Make function that creates this host using host_add"""
        return self.make_command('host_add', self.fqdn,
                                 description=self.description,
                                 l=self.location,
                                 force=force)

    def make_delete_command(self):
        """Make function that deletes the host using host_del"""
        return self.make_command('host_del', self.fqdn)

    def make_retrieve_command(self, all=False, raw=False):
        """Make function that retrieves the host using host_show"""
        return self.make_command('host_show', self.fqdn, all=all, raw=raw)

    def make_find_command(self, *args, **kwargs):
        """Make function that finds hosts using host_find

        Note that the fqdn (or other search terms) needs to be specified
        in arguments.
        """
        return self.make_command('host_find', *args, **kwargs)

    def make_update_command(self, updates):
        """Make function that modifies the host using host_mod"""
        return self.make_command('host_mod', self.fqdn, **updates)

    def track_create(self):
        """Update expected state for host creation"""
        self.attrs = dict(
            dn=self.dn,
            fqdn=[self.fqdn],
            description=[self.description],
            l=[self.location],
            krbprincipalname=[u'host/%s@%s' % (self.fqdn, self.api.env.realm)],
            objectclass=objectclasses.host,
            ipauniqueid=[fuzzy_uuid],
            managedby_host=[self.fqdn],
            has_keytab=False,
            has_password=False,
            cn=[self.fqdn],
            ipakrbokasdelegate=False,
            ipakrbrequirespreauth=True,
            managing_host=[self.fqdn],
            serverhostname=[self.shortname],
        )
        self.exists = True

    def check_create(self, result):
        """Check `host_add` command result"""
        assert_deepequal(dict(
            value=self.fqdn,
            summary=u'Added host "%s"' % self.fqdn,
            result=self.filter_attrs(self.create_keys),
        ), result)

    def check_delete(self, result):
        """Check `host_del` command result"""
        assert_deepequal(dict(
            value=[self.fqdn],
            summary=u'Deleted host "%s"' % self.fqdn,
            result=dict(failed=[]),
        ), result)

    def check_retrieve(self, result, all=False, raw=False):
        """Check `host_show` command result"""
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(dict(
            value=self.fqdn,
            summary=None,
            result=expected,
        ), result)

    def check_find(self, result, all=False, raw=False):
        """Check `host_find` command result"""
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)
        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 host matched',
            result=[expected],
        ), result)

    def check_update(self, result, extra_keys=()):
        """Check `host_update` command result"""
        assert_deepequal(dict(
            value=self.fqdn,
            summary=u'Modified host "%s"' % self.fqdn,
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)


@pytest.fixture(scope='class')
def host(request):
    tracker = HostTracker(name=u'testhost1')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host2(request):
    tracker = HostTracker(name=u'testhost2')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def host3(request):
    tracker = HostTracker(name=u'testhost3')
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def lab_host(request):
    name = u'testhost1'
    tracker = HostTracker(name=name,
                          fqdn=u'%s.lab.%s' % (name, api.env.domain))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def this_host(request):
    """Fixture for the current master"""
    tracker = HostTracker(name=api.env.host.partition('.')[0],
                          fqdn=api.env.host)
    # This host is not created/deleted, so don't call make_fixture
    tracker.exists = True
    return tracker


@pytest.fixture(scope='class')
def invalid_host(request):
    tracker = HostTracker(name='foo_bar',)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv6only_host(request):
    name = u'testipv6onlyhost'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv4only_host(request):
    name = u'testipv4onlyhost'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv46both_host(request):
    name = u'testipv4and6host'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv4_fromip_host(request):
    name = u'testipv4fromip'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def ipv6_fromip_host(request):
    name = u'testipv6fromip'
    tracker = HostTracker(name=name, fqdn=u'%s.%s' % (name, dnszone))
    return tracker.make_fixture(request)


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
                        md5_fingerprint=fuzzy_hash,
                        serial_number=fuzzy_digits,
                        serial_number_hex=fuzzy_hex,
                        sha1_fingerprint=fuzzy_hash,
                        subject=DN(('CN', api.env.host), x509.subject_base()),
                        valid_not_before=fuzzy_date,
                        valid_not_after=fuzzy_date,
                    ))
        host.retrieve()

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
        with raises_exact(errors.DNSNotARecordError(
                reason=u'Host does not have corresponding DNS A/AAAA record')):
            command()

    def test_add_host_with_null_password(self, host):
        host.ensure_missing()
        command = host.make_create_command()
        result = command(userpassword=None)
        host.track_create()
        host.check_create(result)


class TestMultipleMatches(XMLRPC_test):
    def test_try_show_multiple_matches_with_shortname(self, host, lab_host):
        host.ensure_exists()
        lab_host.ensure_exists()
        assert host.shortname == lab_host.shortname
        command = host.make_command('host_show', host.shortname)
        with pytest.raises(errors.SingleMatchExpected):
            command()


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
            result=[host.filter_attrs(host.retrieve_keys)],
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


@pytest.yield_fixture
def keytabname(request):
    keytabfd, keytabname = tempfile.mkstemp()
    try:
        os.close(keytabfd)
        yield keytabname
    finally:
        os.unlink(keytabname)


class TestHostFalsePwdChange(XMLRPC_test):

    def test_join_host(self, host, keytabname):
        """
        Create a test host and join it into IPA.
        """

        join_command = 'ipa-client/ipa-join'
        if not os.path.isfile(join_command):
            pytest.skip("Command '%s' not found" % join_command)

        # create a test host with bulk enrollment password
        host.track_create()
        del host.attrs['krbprincipalname']
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
            join_command,
            "-s", host.api.env.host,
            "-h", host.fqdn,
            "-k", keytabname,
            "-w", random_pass,
            "-q",
        ]

        try:
            out, err, rc = ipautil.run(new_args)
        except ipautil.CalledProcessError as e:
            # join operation may fail on 'adding key into keytab', but
            # the keytab is not necessary for further tests
            print e

        host.attrs['has_keytab'] = True
        host.attrs['has_password'] = False
        host.attrs['krbprincipalname'] = [u'host/%s@%s' % (host.fqdn,
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


@pytest.yield_fixture(scope='class')
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


class TestHostDNS(XMLRPC_test):
    def test_add_ipv6only_host(self, dns_setup, ipv6only_host):
        ipv6only_host.run_command('dnsrecord_add', dnszone,
                                  ipv6only_host.shortname, aaaarecord=aaaarec)
        try:
            ipv6only_host.create(force=False)
        finally:
            command = ipv6only_host.run_command('dnsrecord_del', dnszone,
                                                ipv6only_host.shortname,
                                                aaaarecord=aaaarec)

    def test_add_ipv4only_host(self, dns_setup, ipv4only_host):
        ipv4only_host.run_command('dnsrecord_add', dnszone,
                                  ipv4only_host.shortname, arecord=arec)
        try:
            ipv4only_host.create(force=False)
        finally:
            command = ipv4only_host.run_command('dnsrecord_del', dnszone,
                                                ipv4only_host.shortname,
                                                arecord=arec)

    def test_add_ipv46both_host(self, dns_setup, ipv46both_host):
        ipv46both_host.run_command('dnsrecord_add', dnszone,
                                   ipv46both_host.shortname,
                                   arecord=arec2, aaaarecord=aaaarec2)
        try:
            ipv46both_host.create(force=False)
        finally:
            command = ipv46both_host.run_command('dnsrecord_del', dnszone,
                                                 ipv46both_host.shortname,
                                                 arecord=arec2,
                                                 aaaarecord=aaaarec2)

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
