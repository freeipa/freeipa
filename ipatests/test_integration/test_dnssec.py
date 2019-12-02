#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging
import re
import subprocess
import time

import dns.dnssec
import dns.resolver
import dns.name

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

# Sleep 5 seconds at most when waiting for LDAP updates
# for DNSSEC changes. Test zones should be updated with 1 second TTL
DNSSEC_SLEEP = 5

test_zone = "dnssec.test."
test_zone_repl = "dnssec-replica.test."
root_zone = "."
example_test_zone = "example.test."
example2_test_zone = "example2.test."
example3_test_zone = "example3.test."


def resolve_with_dnssec(nameserver, query, rtype="SOA"):
    res = dns.resolver.Resolver()
    res.nameservers = [nameserver]
    res.lifetime = 10  # wait max 10 seconds for reply
    # enable Authenticated Data + Checking Disabled flags
    res.set_flags(dns.flags.AD | dns.flags.CD)

    # enable EDNS v0 + enable DNSSEC-Ok flag
    res.use_edns(0, dns.flags.DO, 0)

    ans = res.query(query, rtype)
    return ans


def get_RRSIG_record(nameserver, query, rtype="SOA"):
    ans = resolve_with_dnssec(nameserver, query, rtype=rtype)
    return ans.response.find_rrset(
        ans.response.answer, dns.name.from_text(query),
        dns.rdataclass.IN, dns.rdatatype.RRSIG,
        dns.rdatatype.from_text(rtype))


def is_record_signed(nameserver, query, rtype="SOA"):
    try:
        get_RRSIG_record(nameserver, query, rtype=rtype)
    except KeyError:
        return False
    except dns.exception.DNSException:
        return False
    return True


def wait_until_record_is_signed(nameserver, record, rtype="SOA",
                                timeout=100):
    """
    Returns True if record is signed, or False on timeout
    :param nameserver: nameserver to query
    :param record: query
    :param rtype: record type
    :param timeout:
    :return: True if records is signed, False if timeout
    """
    logger.info("Waiting for signed %s record of %s from server %s (timeout "
                "%s sec)", rtype, record, nameserver, timeout)
    wait_until = time.time() + timeout
    while time.time() < wait_until:
        if is_record_signed(nameserver, record, rtype=rtype):
            return True
        time.sleep(1)
    return False


def dnszone_add_dnssec(host, test_zone):
    """Add dnszone with dnssec and short TTL
    """
    args = [
        "ipa",
        "dnszone-add", test_zone,
        "--skip-overlap-check",
        "--dnssec", "true",
        "--ttl", "1",
        "--default-ttl", "1",
    ]
    return host.run_command(args)


def dnssec_install_master(host):
    args = [
        "ipa-dns-install",
        "--dnssec-master",
        "--forwarder", host.config.dns_forwarder,
        "-U",
    ]
    return host.run_command(args)


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
        dnssec_install_master(self.master)

    def test_if_zone_is_signed_master(self):
        # add zone with enabled DNSSEC signing on master
        dnszone_add_dnssec(self.master, test_zone)
        # test master
        assert wait_until_record_is_signed(
            self.master.ip, test_zone, timeout=100
        ), "Zone %s is not signed (master)" % test_zone

        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, test_zone, timeout=200
        ), "DNS zone %s is not signed (replica)" % test_zone

    def test_if_zone_is_signed_replica(self):
        # add zone with enabled DNSSEC signing on replica
        dnszone_add_dnssec(self.replicas[0], test_zone_repl)
        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, test_zone_repl, timeout=300
        ), "Zone %s is not signed (replica)" % test_zone_repl

        # we do not need to wait, on master zones should be singed faster
        # than on replicas

        assert wait_until_record_is_signed(
            self.master.ip, test_zone_repl, timeout=5
        ), "DNS zone %s is not signed (master)" % test_zone

    def test_disable_reenable_signing_master(self):
        dnskey_old = resolve_with_dnssec(self.master.ip, test_zone,
                                         rtype="DNSKEY").rrset

        # disable DNSSEC signing of zone on master
        args = [
            "ipa",
            "dnszone-mod", test_zone,
            "--dnssec", "false",
        ]
        self.master.run_command(args)

        time.sleep(DNSSEC_SLEEP)

        # test master
        assert not is_record_signed(
            self.master.ip, test_zone
        ), "Zone %s is still signed (master)" % test_zone

        # test replica
        assert not is_record_signed(
            self.replicas[0].ip, test_zone
        ), "DNS zone %s is still signed (replica)" % test_zone

        # reenable DNSSEC signing
        args = [
            "ipa",
            "dnszone-mod", test_zone,
            "--dnssec", "true",
        ]
        self.master.run_command(args)

        # TODO: test require restart
        tasks.restart_named(self.master, self.replicas[0])
        # test master
        assert wait_until_record_is_signed(
            self.master.ip, test_zone, timeout=100
        ), "Zone %s is not signed (master)" % test_zone

        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, test_zone, timeout=200
        ), "DNS zone %s is not signed (replica)" % test_zone

        dnskey_new = resolve_with_dnssec(self.master.ip, test_zone,
                                         rtype="DNSKEY").rrset
        assert dnskey_old != dnskey_new, "DNSKEY should be different"

    def test_disable_reenable_signing_replica(self):
        dnskey_old = resolve_with_dnssec(self.replicas[0].ip, test_zone_repl,
                                         rtype="DNSKEY").rrset

        # disable DNSSEC signing of zone on replica
        args = [
            "ipa",
            "dnszone-mod", test_zone_repl,
            "--dnssec", "false",
        ]
        self.master.run_command(args)

        time.sleep(DNSSEC_SLEEP)

        # test master
        assert not is_record_signed(
            self.master.ip, test_zone_repl
        ), "Zone %s is still signed (master)" % test_zone_repl

        # test replica
        assert not is_record_signed(
            self.replicas[0].ip, test_zone_repl
        ), "DNS zone %s is still signed (replica)" % test_zone_repl

        # reenable DNSSEC signing
        args = [
            "ipa",
            "dnszone-mod", test_zone_repl,
            "--dnssec", "true",
        ]
        self.master.run_command(args)

        # TODO: test require restart
        tasks.restart_named(self.master, self.replicas[0])
        # test master
        assert wait_until_record_is_signed(
            self.master.ip, test_zone_repl, timeout=100
        ), "Zone %s is not signed (master)" % test_zone_repl

        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, test_zone_repl, timeout=200
        ), "DNS zone %s is not signed (replica)" % test_zone_repl

        dnskey_new = resolve_with_dnssec(self.replicas[0].ip, test_zone_repl,
                                         rtype="DNSKEY").rrset
        assert dnskey_old != dnskey_new, "DNSKEY should be different"


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
            "-U",
        ]
        cls.master.run_command(args)
        # Enable dns service on master as it has been installed without dns
        # support before
        Firewall(cls.master).enable_services(["dns"])

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
        dnszone_add_dnssec(self.master, root_zone)

        # make BIND happy: add the glue record and delegate zone
        args = [
            "ipa", "dnsrecord-add", root_zone, self.master.hostname,
            "--a-rec=" + self.master.ip
        ]
        self.master.run_command(args)
        args = [
            "ipa", "dnsrecord-add", root_zone, self.replicas[0].hostname,
            "--a-rec=" + self.replicas[0].ip
        ]
        self.master.run_command(args)
        time.sleep(DNSSEC_SLEEP)

        args = [
            "ipa", "dnsrecord-add", root_zone, self.master.domain.name,
            "--ns-rec=" + self.master.hostname
        ]
        self.master.run_command(args)
        # test master
        assert wait_until_record_is_signed(
            self.master.ip, root_zone, timeout=100
        ), "Zone %s is not signed (master)" % root_zone

        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, root_zone, timeout=300
        ), "Zone %s is not signed (replica)" % root_zone

    @pytest.mark.xfail(reason='dnspython issue 343', strict=False)
    def test_chain_of_trust(self):
        """
        Validate signed DNS records, using our own signed root zone
        :return:
        """
        dnszone_add_dnssec(self.master, example_test_zone)

        # delegation
        args = [
            "ipa", "dnsrecord-add", root_zone, example_test_zone,
            "--ns-rec=" + self.master.hostname
        ]
        self.master.run_command(args)

        # TODO: test require restart
        tasks.restart_named(self.master, self.replicas[0])

        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.master.ip, example_test_zone, timeout=100
        ), "Zone %s is not signed (master)" % example_test_zone
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.replicas[0].ip, example_test_zone, timeout=200
        ), "Zone %s is not signed (replica)" % example_test_zone

        # GET DNSKEY records from zone
        ans = resolve_with_dnssec(self.master.ip, example_test_zone,
                                  rtype="DNSKEY")
        dnskey_rrset = ans.response.get_rrset(
            ans.response.answer,
            dns.name.from_text(example_test_zone),
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY)
        assert dnskey_rrset, "No DNSKEY records received"

        logger.debug("DNSKEY records returned: %s", dnskey_rrset.to_text())

        # generate DS records
        ds_records = []
        for key_rdata in dnskey_rrset:
            if key_rdata.flags != 257:
                continue  # it is not KSK
            ds_records.append(dns.dnssec.make_ds(example_test_zone, key_rdata,
                                                 'sha256'))
        assert ds_records, ("No KSK returned from the %s zone" %
                            example_test_zone)

        logger.debug("DS records for %s created: %r", example_test_zone,
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

        # wait until DS records it replicated
        assert wait_until_record_is_signed(
            self.replicas[0].ip, example_test_zone, timeout=100,
            rtype="DS"
        ), "No DS record of '%s' returned from replica" % example_test_zone

        # extract DSKEY from root zone
        ans = resolve_with_dnssec(self.master.ip, root_zone,
                                  rtype="DNSKEY")
        dnskey_rrset = ans.response.get_rrset(ans.response.answer,
                                              dns.name.from_text(root_zone),
                                              dns.rdataclass.IN,
                                              dns.rdatatype.DNSKEY)
        assert dnskey_rrset, "No DNSKEY records received"

        logger.debug("DNSKEY records returned: %s", dnskey_rrset.to_text())

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
        logger.debug("Root zone trusted key: %s", root_keys_rrset.to_text())

        # set trusted key for our root zone
        self.master.put_file_contents(paths.DNSSEC_TRUSTED_KEY,
                                      root_keys_rrset.to_text() + '\n')
        self.replicas[0].put_file_contents(paths.DNSSEC_TRUSTED_KEY,
                                           root_keys_rrset.to_text() + '\n')

        # verify signatures
        time.sleep(DNSSEC_SLEEP)
        args = [
            "drill", "@localhost", "-k",
            paths.DNSSEC_TRUSTED_KEY, "-S",
            example_test_zone, "SOA"
        ]

        # test if signature chains are valid
        self.master.run_command(args)
        self.replicas[0].run_command(args)

    def test_resolvconf(self):
        # check that resolv.conf contains IP address for localhost
        for host in [self.master, self.replicas[0]]:
            resolvconf = host.get_file_contents(paths.RESOLV_CONF, 'utf-8')
            assert any(ip in resolvconf for ip in ('127.0.0.1', '::1'))


class TestMigrateDNSSECMaster(IntegrationTest):
    """test DNSSEC master migration

    Install a server and a replica with DNS, then reinstall server
    as DNSSEC master
    Test:
     * migrate dnssec master to replica
     * create new zone
     * verify if zone is signed on all replicas
     * add new replica
     * add new zone
     * test if new zone is signed on all replicas
    """
    num_replicas = 2
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        args = [
            "ipa-dns-install",
            "--dnssec-master",
            "--forwarder", cls.master.config.dns_forwarder,
            "-U",
        ]
        cls.master.run_command(args)
        # No need to enable dns service in the firewall as master has been
        # installed with dns support enabled
        # Firewall(cls.master).enable_services(["dns"])
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True)

    @classmethod
    def uninstall(cls, mh):
        # For this test, we need to uninstall DNSSEC master last
        # Find which server is DNSSec master
        result = cls.master.run_command(["ipa", "config-show"]).stdout_text
        matches = list(re.finditer('IPA DNSSec key master: (.*)', result))
        if len(matches) == 1:
            # Found the DNSSec master
            dnssec_master_hostname = matches[0].group(1)
            for replica in cls.replicas + [cls.master]:
                if replica.hostname == dnssec_master_hostname:
                    dnssec_master = replica
        else:
            # By default consider that the master is DNSSEC
            dnssec_master = cls.master

        for replica in cls.replicas + [cls.master]:
            if replica == dnssec_master:
                # Skip this one
                continue
            try:
                tasks.run_server_del(
                    dnssec_master, replica.hostname, force=True,
                    ignore_topology_disconnect=True, ignore_last_of_role=True)
            except subprocess.CalledProcessError:
                # If the master has already been uninstalled,
                # this call may fail
                pass
            tasks.uninstall_master(replica)
        tasks.uninstall_master(dnssec_master)

    def test_migrate_dnssec_master(self):
        """Both master and replica have DNS installed"""
        backup_filename = "/var/lib/ipa/ipa-kasp.db.backup"
        replica_backup_filename = "/tmp/ipa-kasp.db.backup"

        # add test zone
        dnszone_add_dnssec(self.master, example_test_zone)
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.master.ip, example_test_zone, timeout=100
        ), "Zone %s is not signed (master)" % example_test_zone
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.replicas[0].ip, example_test_zone, timeout=200
        ), "Zone %s is not signed (replica)" % example_test_zone

        dnskey_old = resolve_with_dnssec(self.master.ip, example_test_zone,
                                         rtype="DNSKEY").rrset

        # migrate dnssec master to replica
        args = [
            "ipa-dns-install",
            "--disable-dnssec-master",
            "--forwarder", self.master.config.dns_forwarder,
            "--force",
            "-U",
        ]
        self.master.run_command(args)

        # move content of "ipa-kasp.db.backup" to replica
        kasp_db_backup = self.master.get_file_contents(backup_filename)
        self.replicas[0].put_file_contents(replica_backup_filename,
                                           kasp_db_backup)

        args = [
            "ipa-dns-install",
            "--dnssec-master",
            "--kasp-db", replica_backup_filename,
            "--forwarder", self.master.config.dns_forwarder,
            "-U",
        ]
        self.replicas[0].run_command(args)
        # Enable the dns service in the firewall on the replica
        Firewall(self.replicas[0]).enable_services(["dns"])

        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.master.ip, example_test_zone, timeout=100
        ), "Zone %s is not signed after migration (master)" % example_test_zone
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.replicas[0].ip, example_test_zone, timeout=200
        ), "Zone %s is not signed after migration (replica)" % example_test_zone

        # test if dnskey are the same
        dnskey_new = resolve_with_dnssec(self.master.ip, example_test_zone,
                                         rtype="DNSKEY").rrset
        assert dnskey_old == dnskey_new, "DNSKEY should be the same"

        # add test zone
        dnszone_add_dnssec(self.replicas[0], example2_test_zone)
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.replicas[0].ip, example2_test_zone, timeout=100
        ), ("Zone %s is not signed after migration (replica - dnssec master)"
            % example2_test_zone)
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.master.ip, example2_test_zone, timeout=200
        ), ("Zone %s is not signed after migration (master)"
            % example2_test_zone)

        # add new replica
        tasks.install_replica(self.master, self.replicas[1], setup_dns=True)

        # test if originial zones are signed on new replica
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.replicas[1].ip, example_test_zone, timeout=200
        ), ("Zone %s is not signed (new replica)"
            % example_test_zone)
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.replicas[1].ip, example2_test_zone, timeout=200
        ), ("Zone %s is not signed (new replica)"
            % example2_test_zone)

        # add new zone to new replica
        dnszone_add_dnssec(self.replicas[0], example3_test_zone)
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.replicas[1].ip, example3_test_zone, timeout=200
        ), ("Zone %s is not signed (new replica)"
            % example3_test_zone)
        assert wait_until_record_is_signed(
            self.replicas[0].ip, example3_test_zone, timeout=200
        ), ("Zone %s is not signed (replica)"
            % example3_test_zone)
        # wait until zone is signed
        assert wait_until_record_is_signed(
            self.master.ip, example3_test_zone, timeout=200
        ), ("Zone %s is not signed (master)"
            % example3_test_zone)


class TestInstallNoDnssecValidation(IntegrationTest):
    """test installation of the master with
    --no-dnssec-validation

    Test for issue 7666: ipa-server-install --setup-dns is failing
    if using --no-dnssec-validation and --forwarder, when the
    specified forwarder does not support DNSSEC.
    The forwarder should not be checked for DNSSEC support when
    --no-dnssec-validation argument is specified.
    In order to reproduce the conditions, the test is using a dummy
    IP address for the forwarder (i.e. there is no BIND service available
    at this IP address). To make sure of that, the test is using the IP of
    a replica (that is not yet setup).
    """
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        cls.install_args = [
            'ipa-server-install',
            '-n', cls.master.domain.name,
            '-r', cls.master.domain.realm,
            '-p', cls.master.config.dirman_password,
            '-a', cls.master.config.admin_password,
            '-U',
            '--setup-dns',
            '--forwarder', cls.replicas[0].ip,
            '--auto-reverse'
        ]

    def test_install_withDnssecValidation(self):
        cmd = self.master.run_command(self.install_args, raiseonerr=False)
        # The installer checks that the forwarder supports DNSSEC
        # but the forwarder does not answer => expect failure
        assert cmd.returncode != 0

    def test_install_noDnssecValidation(self):
        # With the --no-dnssec-validation, the installer does not check
        # whether the forwarder supports DNSSEC => success even if the
        # forwarder is not reachable
        self.master.run_command(
            self.install_args + ['--no-dnssec-validation'])
