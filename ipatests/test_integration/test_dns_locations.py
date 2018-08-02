#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
import logging
import time
import pytest
import six
import dns.resolver
import dns.rrset
import dns.rdatatype
import dns.rdataclass

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipapython.dnsutil import DNSName
from ipalib.constants import IPA_CA_RECORD

logger = logging.getLogger(__name__)

IPA_DEFAULT_MASTER_SRV_REC = (
    # srv record name, port
    (DNSName(u'_ldap._tcp'), 389),
    (DNSName(u'_kerberos._tcp'), 88),
    (DNSName(u'_kerberos._udp'), 88),
    (DNSName(u'_kerberos-master._tcp'), 88),
    (DNSName(u'_kerberos-master._udp'), 88),
    (DNSName(u'_kpasswd._tcp'), 464),
    (DNSName(u'_kpasswd._udp'), 464),
)

IPA_DEFAULT_ADTRUST_SRV_REC = (
    # srv record name, port
    (DNSName(u'_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs'), 389),
    (DNSName(u'_ldap._tcp.dc._msdcs'), 389),
    (DNSName(u'_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs'), 88),
    (DNSName(u'_kerberos._udp.Default-First-Site-Name._sites.dc._msdcs'), 88),
    (DNSName(u'_kerberos._tcp.dc._msdcs'), 88),
    (DNSName(u'_kerberos._udp.dc._msdcs'), 88),
)

IPA_CA_A_REC = (
    (DNSName(six.text_type(IPA_CA_RECORD))),
)


def resolve_records_from_server(rname, rtype, nameserver):
    error = None
    res = dns.resolver.Resolver()
    res.nameservers = [nameserver]
    res.lifetime = 30
    logger.info("Query: %s %s, nameserver %s", rname, rtype, nameserver)
    # lets try to query 3x
    for _i in range(3):
        try:
            ans = res.query(rname, rtype)
            logger.info("Answer: %s", ans.rrset)
            return ans.rrset
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
            error = e
            time.sleep(10)

    pytest.fail("Query: {} {}, nameserver {} failed due to {}".format(
        rname, rtype, nameserver, error))


def _gen_expected_srv_rrset(rname, port, servers, ttl=86400):
    rdata_list = [
        "{prio} {weight} {port} {servername}".format(
            prio=prio,
            weight=weight,
            port=port,
            servername=servername.make_absolute()
        )
        for prio, weight, servername in servers
    ]
    return dns.rrset.from_text_list(
        rname, ttl, dns.rdataclass.IN, dns.rdatatype.SRV, rdata_list
    )


def _gen_expected_a_rrset(rname, servers, ttl=86400):
    return dns.rrset.from_text_list(rname, ttl, dns.rdataclass.IN,
                                    dns.rdatatype.A, servers)


class TestDNSLocations(IntegrationTest):
    """Simple test if SRV DNS records for IPA locations are generated properly

    Topology:
        * 3 servers (replica0 --- master --- replica1)
            replica0 with no CA, master with ADtrust installed later,
            replica1 with CA
        * 2 locations (prague, paris)
    """
    num_replicas = 2
    topology = 'star'

    LOC_PRAGUE = u'prague'
    LOC_PARIS = u'paris'

    PRIO_HIGH = 0
    PRIO_LOW = 50
    WEIGHT = 100

    @classmethod
    def install(cls, mh):
        cls.domain = DNSName(cls.master.domain.name).make_absolute()
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True,
                              setup_ca=False)
        tasks.install_replica(cls.master, cls.replicas[1], setup_dns=True,
                              setup_ca=True)

        for host in (cls.master, cls.replicas[0], cls.replicas[1]):
            ldap = host.ldap_connect()
            tasks.wait_for_replication(ldap)

        # give time to named to retrieve new records
        time.sleep(20)

    @classmethod
    def delete_update_system_records(cls, rnames):
        filepath = '/tmp/ipa.nsupdate'

        cls.master.run_command([
            'ipa', 'dns-update-system-records', '--dry-run', '--out', filepath
        ])

        for name in rnames:
            cls.master.run_command([
                'ipa', 'dnsrecord-del', str(cls.domain), str(name),
                '--del-all'])

        time.sleep(15)
        # allow unauthenticates nsupdate (no need to testing authentication)
        cls.master.run_command([
            'ipa', 'dnszone-mod', str(cls.domain),
            '--update-policy=grant * wildcard *;'
        ], raiseonerr=False)

        cls.master.run_command(['nsupdate', '-g', filepath])
        time.sleep(15)

    def _test_A_rec_against_server(self, server_ip, domain, expected_servers,
                                   rec_list=IPA_CA_A_REC):
        for rname in rec_list:
            name_abs = rname.derelativize(domain)
            expected = _gen_expected_a_rrset(name_abs, expected_servers)
            query = resolve_records_from_server(
                name_abs, 'A', server_ip)

            assert expected == query, (
                "Expected and received DNS data do not match on server "
                "with IP: '{}' for name '{}' (expected:\n{}\ngot:\n{})".
                format(server_ip, name_abs, expected, query))

    def _test_SRV_rec_against_server(self, server_ip, domain, expected_servers,
                                     rec_list=IPA_DEFAULT_MASTER_SRV_REC):
        for rname, port in rec_list:
            name_abs = rname.derelativize(domain)
            expected = _gen_expected_srv_rrset(
                name_abs, port, expected_servers)
            query = resolve_records_from_server(
                name_abs, 'SRV', server_ip)

            assert expected == query, (
                "Expected and received DNS data do not match on server "
                "with IP: '{}' for name '{}' (expected:\n{}\ngot:\n{})".
                format(server_ip, name_abs, expected, query))

    def test_without_locations(self):
        """Servers are not in locations, this tests if basic system records
        are generated properly"""
        expected_servers = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        for ip in (self.master.ip, self.replicas[0].ip, self.replicas[1].ip):
            self._test_SRV_rec_against_server(ip, self.domain,
                                              expected_servers)

    def test_nsupdate_without_locations(self):
        """Test nsupdate file generated by dns-update-system-records
        Remove all records and the use nsupdate to restore state and test if
        all record are there as expected"""

        self.delete_update_system_records(rnames=(r[0] for r in
                                          IPA_DEFAULT_MASTER_SRV_REC))
        self.test_without_locations()

    def test_one_replica_in_location(self):
        """Put one replica to location and test if records changed properly
        """

        # create location prague, replica0 --> location prague
        self.master.run_command([
            'ipa', 'location-add', self.LOC_PRAGUE
        ])
        self.master.run_command([
            'ipa', 'server-mod', self.replicas[0].hostname,
            '--location', self.LOC_PRAGUE
        ])
        tasks.restart_named(self.replicas[0])

        servers_without_loc = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_without_loc = DNSName(self.master.domain.name).make_absolute()

        servers_prague_loc = (
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_prague_loc = (
            DNSName('{}._locations'.format(self.LOC_PRAGUE)) +
            DNSName(self.master.domain.name).make_absolute()
        )

        self._test_SRV_rec_against_server(
            self.replicas[0].ip, domain_prague_loc, servers_prague_loc)

        for ip in (self.master.ip, self.replicas[1].ip):
            self._test_SRV_rec_against_server(
                ip, domain_without_loc, servers_without_loc)

    def test_two_replicas_in_location(self):
        """Put second replica to location and test if records changed properly
        """

        # create location paris, replica1 --> location prague
        self.master.run_command(['ipa', 'location-add', self.LOC_PARIS])
        self.master.run_command([
            'ipa', 'server-mod', self.replicas[1].hostname, '--location',
            self.LOC_PARIS])
        tasks.restart_named(self.replicas[1])

        servers_without_loc = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_without_loc = DNSName(self.master.domain.name).make_absolute()

        servers_prague_loc = (
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_prague_loc = (
            DNSName('{}._locations'.format(self.LOC_PRAGUE)) + DNSName(
                self.master.domain.name).make_absolute())

        servers_paris_loc = (
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_paris_loc = (
            DNSName('{}._locations'.format(self.LOC_PARIS)) + DNSName(
                self.master.domain.name).make_absolute())

        self._test_SRV_rec_against_server(
            self.replicas[0].ip, domain_prague_loc, servers_prague_loc)

        self._test_SRV_rec_against_server(
            self.replicas[1].ip, domain_paris_loc, servers_paris_loc)

        self._test_SRV_rec_against_server(
            self.master.ip, domain_without_loc, servers_without_loc)

    def test_all_servers_in_location(self):
        """Put master (as second server) to location and test if records
        changed properly
        """

        # master --> location paris
        self.master.run_command([
            'ipa', 'server-mod', self.master.hostname, '--location',
            self.LOC_PARIS])
        tasks.restart_named(self.master)

        servers_prague_loc = (
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_prague_loc = (
            DNSName('{}._locations'.format(self.LOC_PRAGUE)) + DNSName(
                self.master.domain.name).make_absolute())

        servers_paris_loc = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_paris_loc = (
            DNSName('{}._locations'.format(self.LOC_PARIS)) + DNSName(
                self.master.domain.name).make_absolute())

        self._test_SRV_rec_against_server(
            self.replicas[0].ip, domain_prague_loc, servers_prague_loc)

        for ip in (self.replicas[1].ip, self.master.ip):
            self._test_SRV_rec_against_server(ip, domain_paris_loc,
                                              servers_paris_loc)

    def test_change_weight(self):
        """Change weight of master and test if records changed properly
        """

        new_weight = 2000

        self.master.run_command([
            'ipa', 'server-mod', self.master.hostname, '--service-weight',
            str(new_weight)
        ])

        # all servers must be restarted
        tasks.restart_named(self.master, self.replicas[0], self.replicas[1])

        servers_prague_loc = (
            (self.PRIO_LOW, new_weight, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_prague_loc = (
            DNSName('{}._locations'.format(self.LOC_PRAGUE)) + DNSName(
                self.master.domain.name).make_absolute())

        servers_paris_loc = (
            (self.PRIO_HIGH, new_weight, DNSName(self.master.hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_paris_loc = (
            DNSName('{}._locations'.format(self.LOC_PARIS)) + DNSName(
                self.master.domain.name).make_absolute())

        self._test_SRV_rec_against_server(
            self.replicas[0].ip, domain_prague_loc, servers_prague_loc)

        for ip in (self.replicas[1].ip, self.master.ip):
            self._test_SRV_rec_against_server(ip, domain_paris_loc,
                                              servers_paris_loc)

    def test_restore_locations_and_weight(self):
        """Restore locations and weight. Not just for test purposes but also
        for the following tests"""

        for hostname in (self.master.hostname, self.replicas[0].hostname,
                         self.replicas[1].hostname):
            self.master.run_command(['ipa', 'server-mod', hostname,
                                     '--location='''])

        self.master.run_command(['ipa', 'location-del', self.LOC_PRAGUE])
        self.master.run_command(['ipa', 'location-del', self.LOC_PARIS])

        self.master.run_command([
            'ipa', 'server-mod', self.master.hostname, '--service-weight',
            str(self.WEIGHT)
        ])

        tasks.restart_named(self.master, self.replicas[0], self.replicas[1])
        time.sleep(5)

    def test_ipa_ca_records(self):
        """ Test ipa-ca dns records with firstly removing the records and then
        using the nsupdate generated by dns-update-system-records"""
        self.delete_update_system_records(rnames=IPA_CA_A_REC)

        expected_servers = (self.master.ip, self.replicas[1].ip)

        for ip in (self.master.ip, self.replicas[0].ip, self.replicas[1].ip):
            self._test_A_rec_against_server(ip, self.domain, expected_servers)


    def test_adtrust_system_records(self):
        """ Test ADTrust dns records with firstly installing a trust then
        removing the records and using the nsupdate generated by
        dns-update-system-records."""
        self.master.run_command(['ipa-adtrust-install', '-U',
                                 '--enable-compat', '--netbios-name', 'IPA',
                                 '-a', self.master.config.admin_password,
                                 '--add-sids'])
        # lets re-kinit after adtrust-install and restart named
        tasks.kinit_admin(self.master)
        tasks.restart_named(self.master)
        time.sleep(5)
        self.delete_update_system_records(rnames=(r[0] for r in
                                          IPA_DEFAULT_ADTRUST_SRV_REC))

        expected_servers = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
        )

        for ip in (self.master.ip, self.replicas[0].ip, self.replicas[1].ip):
            self._test_SRV_rec_against_server(
                    ip, self.domain, expected_servers,
                    rec_list=IPA_DEFAULT_ADTRUST_SRV_REC)

    def test_remove_replica_with_ca(self):
        """Test ipa-ca dns records after removing the replica with CA"""
        tasks.uninstall_replica(self.master, self.replicas[1])

        self.delete_update_system_records(rnames=IPA_CA_A_REC)

        expected_servers = (self.master.ip,)

        self._test_A_rec_against_server(self.master.ip, self.domain,
                                        expected_servers)
