#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import dns.dnssec
import dns.resolver
import dns.name
import time

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration import tasks
from ipaplatform.paths import paths

test_zone = "dnssec.test."
test_zone_repl = "dnssec-replica.test."
root_zone = "."
example_test_zone = "example.test."


def resolve_with_dnssec(nameserver, query, log, rtype="SOA"):
    res = dns.resolver.Resolver()
    res.nameservers = [nameserver]
    res.lifetime = 10  # wait max 10 seconds for reply
    # enable Authenticated Data + Checking Disabled flags
    res.set_flags(dns.flags.AD | dns.flags.CD)

    # enable EDNS v0 + enable DNSSEC-Ok flag
    res.use_edns(0, dns.flags.DO, 0)

    ans = res.query(query, rtype)
    return ans


def is_record_signed(nameserver, query, log, rtype="SOA"):
    try:
        ans = resolve_with_dnssec(nameserver, query, log, rtype=rtype)
        ans.response.find_rrset(ans.response.answer, dns.name.from_text(query),
                                dns.rdataclass.IN, dns.rdatatype.RRSIG,
                                dns.rdatatype.from_text(rtype))
    except KeyError:
        return False
    except dns.exception.DNSException:
        return False
    return True


def wait_until_record_is_signed(nameserver, record, log, rtype="SOA",
                                timeout=100):
    """
    Returns True if record is signed, or False on timeout
    :param nameserver: nameserver to query
    :param record: query
    :param log: logger
    :param rtype: record type
    :param timeout:
    :return: True if records is signed, False if timeout
    """
    log.info("Waiting for signed %s record of %s from server %s (timeout %s "
             "sec)", rtype, record, nameserver, timeout)
    wait_until = time.time() + timeout
    while time.time() < wait_until:
        if is_record_signed(nameserver, record, log, rtype=rtype):
            return True
        time.sleep(1)
    return False


class TestInstallDNSSECLast(IntegrationTest):
    """Simple DNSSEC test

    Install a server and a replica with DNS, then reinstall server
    as DNSSEC master
    """
    num_replicas = 1
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True)

    def test_install_dnssec_master(self):
        """Both master and replica have DNS installed"""
        args = [
            "ipa-dns-install",
            "--dnssec-master",
            "--forwarder", self.master.config.dns_forwarder,
            "-p", self.master.config.dirman_password,
            "-U",
        ]
        self.master.run_command(args)

    def test_if_zone_is_signed_master(self):
        # add zone with enabled DNSSEC signing on master
        args = [
            "ipa",
            "dnszone-add", test_zone,
            "--dnssec", "true",
        ]
        self.master.run_command(args)

        # test master
        assert wait_until_record_is_signed(
            self.master.ip, test_zone, self.log, timeout=100
        ), "Zone %s is not signed (master)" % test_zone

        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, test_zone, self.log, timeout=200
        ), "DNS zone %s is not signed (replica)" % test_zone

    def test_if_zone_is_signed_replica(self):
        # add zone with enabled DNSSEC signing on replica
        args = [
            "ipa",
            "dnszone-add", test_zone_repl,
            "--dnssec", "true",
        ]
        self.replicas[0].run_command(args)

        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, test_zone_repl, self.log, timeout=300
        ), "Zone %s is not signed (replica)" % test_zone_repl

        # we do not need to wait, on master zones should be singed faster
        # than on replicas

        assert wait_until_record_is_signed(
            self.master.ip, test_zone_repl, self.log, timeout=5
        ), "DNS zone %s is not signed (master)" % test_zone


class TestInstallDNSSECFirst(IntegrationTest):
    """Simple DNSSEC test

    Install the server with DNSSEC and then install the replica with DNS
    """
    num_replicas = 1
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)
        args = [
            "ipa-dns-install",
            "--dnssec-master",
            "--forwarder", cls.master.config.dns_forwarder,
            "-p", cls.master.config.dirman_password,
            "-U",
        ]
        cls.master.run_command(args)

        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True)

        # backup trusted key
        tasks.backup_file(cls.master, paths.DNSSEC_TRUSTED_KEY)
        tasks.backup_file(cls.replicas[0], paths.DNSSEC_TRUSTED_KEY)

    @classmethod
    def uninstall(cls, mh):
        # restore trusted key
        tasks.restore_files(cls.master)
        tasks.restore_files(cls.replicas[0])

        super(TestInstallDNSSECFirst, cls).uninstall(mh)

    def test_sign_root_zone(self):
        args = [
            "ipa", "dnszone-add", root_zone, "--dnssec", "true"
        ]
        self.master.run_command(args)

        # make BIND happy, and delegate zone which contains A record of master
        args = [
            "ipa", "dnsrecord-add", root_zone, self.master.domain.name,
            "--ns-rec=" + self.master.hostname
        ]
        self.master.run_command(args)

        # test master
        assert wait_until_record_is_signed(
            self.master.ip, root_zone, self.log, timeout=100
        ), "Zone %s is not signed (master)" % root_zone

        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, root_zone, self.log, timeout=300
        ), "Zone %s is not signed (replica)" % root_zone

    def test_chain_of_trust(self):
        """
        Validate signed DNS records, using our own signed root zone
        :return:
        """

        # add test zone
        args = [
            "ipa", "dnszone-add", example_test_zone, "--dnssec", "true"
        ]

        self.master.run_command(args)

        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.master.ip, example_test_zone, self.log, timeout=100
        ), "Zone %s is not signed (master)" % example_test_zone

        # GET DNSKEY records from zone
        ans = resolve_with_dnssec(self.master.ip, example_test_zone, self.log,
                                  rtype="DNSKEY")
        dnskey_rrset = ans.response.get_rrset(
            ans.response.answer,
            dns.name.from_text(example_test_zone),
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY)
        assert dnskey_rrset, "No DNSKEY records received"

        self.log.debug("DNSKEY records returned: %s", dnskey_rrset.to_text())

        # generate DS records
        ds_records = []
        for key_rdata in dnskey_rrset:
            if key_rdata.flags != 257:
                continue  # it is not KSK
            ds_records.append(dns.dnssec.make_ds(example_test_zone, key_rdata,
                                                 'sha256'))
        assert ds_records, ("No KSK returned from the %s zone" %
                            example_test_zone)

        self.log.debug("DS records for %s created: %r", example_test_zone,
                       ds_records)

        # add DS records to root zone
        args = [
            "ipa", "dnsrecord-add", root_zone, example_test_zone,
            # DS record requires to coexists with NS
            "--ns-rec", self.master.hostname,
        ]
        for ds in ds_records:
            args.append("--ds-rec")
            args.append(ds.to_text())

        self.master.run_command(args)

        # extract DSKEY from root zone
        ans = resolve_with_dnssec(self.master.ip, root_zone, self.log,
                                  rtype="DNSKEY")
        dnskey_rrset = ans.response.get_rrset(ans.response.answer,
                                              dns.name.from_text(root_zone),
                                              dns.rdataclass.IN,
                                              dns.rdatatype.DNSKEY)
        assert dnskey_rrset, "No DNSKEY records received"

        self.log.debug("DNSKEY records returned: %s", dnskey_rrset.to_text())

        # export trust keys for root zone
        root_key_rdatas = []
        for key_rdata in dnskey_rrset:
            if key_rdata.flags != 257:
                continue  # it is not KSK
            root_key_rdatas.append(key_rdata)

        assert root_key_rdatas, "No KSK returned from the root zone"

        root_keys_rrset = dns.rrset.from_rdata_list(dnskey_rrset.name,
                                                    dnskey_rrset.ttl,
                                                    root_key_rdatas)
        self.log.debug("Root zone trusted key: %s", root_keys_rrset.to_text())

        # set trusted key for our root zone
        self.master.put_file_contents(paths.DNSSEC_TRUSTED_KEY,
                                      root_keys_rrset.to_text() + '\n')
        self.replicas[0].put_file_contents(paths.DNSSEC_TRUSTED_KEY,
                                           root_keys_rrset.to_text() + '\n')

        # verify signatures
        args = [
            "drill", "@localhost", "-k",
            paths.DNSSEC_TRUSTED_KEY, "-S",
            example_test_zone, "SOA"
        ]

        # test if signature chains are valid
        self.master.run_command(args)
        self.replicas[0].run_command(args)
