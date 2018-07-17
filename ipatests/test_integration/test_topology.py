#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import re

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_plugins.integration import tasks
from ipatests.pytest_plugins.integration.env_config import get_global_config
from ipalib.constants import DOMAIN_SUFFIX_NAME
from ipatests.util import assert_deepequal

config = get_global_config()
reasoning = "Topology plugin disabled due to domain level 0"


def find_segment(master, replica):
    result = master.run_command(['ipa', 'topologysegment-find',
                                 DOMAIN_SUFFIX_NAME]).stdout_text
    segment_re = re.compile('Left node: (?P<left>\S+)\n.*Right node: '
                            '(?P<right>\S+)\n')
    allsegments = segment_re.findall(result)
    for segment in allsegments:
        if master.hostname in segment and replica.hostname in segment:
            return '-to-'.join(segment)


@pytest.mark.skipif(config.domain_level == 0, reason=reasoning)
class TestTopologyOptions(IntegrationTest):
    num_replicas = 2
    topology = 'star'
    rawsegment_re = ('Segment name: (?P<name>.*?)',
                     '\s+Left node: (?P<lnode>.*?)',
                     '\s+Right node: (?P<rnode>.*?)',
                     '\s+Connectivity: (?P<connectivity>\S+)')
    segment_re = re.compile("\n".join(rawsegment_re))
    noentries_re = re.compile("Number of entries returned (\d+)")
    segmentnames_re = re.compile('.*Segment name: (\S+?)\n.*')

    @classmethod
    def install(cls, mh):
        tasks.install_topo(cls.topology, cls.master,
                           cls.replicas[:-1],
                           cls.clients)

    def tokenize_topologies(self, command_output):
        """
        takes an output of `ipa topologysegment-find` and returns an array of
        segment hashes
        """
        segments = command_output.split("-----------------")[2]
        raw_segments = segments.split('\n\n')
        result = []
        for i in raw_segments:
            matched = self.segment_re.search(i)
            if matched:
                result.append({'leftnode': matched.group('lnode'),
                               'rightnode': matched.group('rnode'),
                               'name': matched.group('name'),
                               'connectivity': matched.group('connectivity')
                               }
                              )
        return result


    def test_topology_updated_on_replica_install_remove(self):
        """
        Install and remove a replica and make sure topology information is
        updated on all other replicas
        Testcase: http://www.freeipa.org/page/V4/Manage_replication_topology/
        Test_plan#Test_case:
        _Replication_topology_should_be_saved_in_the_LDAP_tree
        """
        tasks.kinit_admin(self.master)
        result1 = self.master.run_command(['ipa', 'topologysegment-find',
                                           DOMAIN_SUFFIX_NAME]).stdout_text
        segment_name = self.segmentnames_re.findall(result1)[0]
        assert(self.master.hostname in segment_name), (
            "Segment %s does not contain master hostname" % segment_name)
        assert(self.replicas[0].hostname in segment_name), (
            "Segment %s does not contain replica hostname" % segment_name)
        tasks.install_replica(self.master, self.replicas[1], setup_ca=False,
                              setup_dns=False)
        # We need to make sure topology information is consistent across all
        # replicas
        result2 = self.master.run_command(['ipa', 'topologysegment-find',
                                           DOMAIN_SUFFIX_NAME])
        result3 = self.replicas[0].run_command(['ipa', 'topologysegment-find',
                                                DOMAIN_SUFFIX_NAME])
        result4 = self.replicas[1].run_command(['ipa', 'topologysegment-find',
                                                DOMAIN_SUFFIX_NAME])
        segments = self.tokenize_topologies(result2.stdout_text)
        assert(len(segments) == 2), "Unexpected number of segments found"
        assert_deepequal(result2.stdout_text, result3.stdout_text)
        assert_deepequal(result3.stdout_text,  result4.stdout_text)
        # Now let's check that uninstalling the replica will update the topology
        # info on the rest of replicas.
        # first step of uninstallation is removal of the replica on other
        # master, then it can be uninstalled. Doing it the other way is also
        # possible, but not reliable - some data might not be replicated.
        tasks.clean_replication_agreement(self.master, self.replicas[1])
        tasks.uninstall_master(self.replicas[1])
        result5 = self.master.run_command(['ipa', 'topologysegment-find',
                                           DOMAIN_SUFFIX_NAME])
        num_entries = self.noentries_re.search(result5.stdout_text).group(1)
        assert(num_entries == "1"), "Incorrect number of entries displayed"

    def test_add_remove_segment(self):
        """
        Make sure a topology segment can be manually created and deleted
        with the influence on the real topology
        Testcase http://www.freeipa.org/page/V4/Manage_replication_topology/
        Test_plan#Test_case:_Basic_CRUD_test
        """
        tasks.kinit_admin(self.master)
        # Install the second replica
        tasks.install_replica(self.master, self.replicas[1], setup_ca=False,
                              setup_dns=False)
        # turn a star into a ring
        segment, err = tasks.create_segment(self.master,
                                            self.replicas[0],
                                            self.replicas[1])
        assert err == "", err
        # Make sure the new segment is shown by `ipa topologysegment-find`
        result1 = self.master.run_command(['ipa', 'topologysegment-find',
                                           DOMAIN_SUFFIX_NAME]).stdout_text
        assert(segment['name'] in result1), (
            "%s: segment not found" % segment['name'])
        # Remove master <-> replica2 segment and make sure that the changes get
        # there through replica1
        # Since segment name can be one of master-to-replica2 or
        # replica2-to-master, we need to determine the segment name dynamically

        deleteme = find_segment(self.master, self.replicas[1])
        returncode, error = tasks.destroy_segment(self.master, deleteme)
        assert returncode == 0, error
        # Wait till replication ends and make sure replica1 does not have
        # segment that was deleted on master
        replica1_ldap = self.replicas[0].ldap_connect()
        tasks.wait_for_replication(replica1_ldap)
        result3 = self.replicas[0].run_command(['ipa', 'topologysegment-find',
                                               DOMAIN_SUFFIX_NAME]).stdout_text
        assert(deleteme not in result3), "%s: segment still exists" % deleteme
        # Create test data on master and make sure it gets all the way down to
        # replica2 through replica1
        self.master.run_command(['ipa', 'user-add', 'someuser',
                                 '--first', 'test',
                                 '--last', 'user'])
        dest_ldap = self.replicas[1].ldap_connect()
        tasks.wait_for_replication(dest_ldap)
        result4 = self.replicas[1].run_command(['ipa', 'user-find'])
        assert('someuser' in result4.stdout_text), 'User not found: someuser'
        # We end up having a line topology: master <-> replica1 <-> replica2

    def test_remove_the_only_connection(self):
        """
        Testcase: http://www.freeipa.org/page/V4/Manage_replication_topology/
        Test_plan#Test_case:
        _Removal_of_a_topology_segment_is_allowed_only_if_there_is_at_least_one_more_segment_connecting_the_given_replica
        """
        text = "Removal of Segment disconnects topology"
        error1 = "The system should not have let you remove the segment"
        error2 = "Wrong error message thrown during segment removal: \"%s\""
        replicas = (self.replicas[0].hostname, self.replicas[1].hostname)

        returncode, error = tasks.destroy_segment(self.master, "%s-to-%s" % replicas)
        assert returncode != 0, error1
        assert error.count(text) == 1, error2 % error
        _newseg, err = tasks.create_segment(
            self.master, self.master, self.replicas[1])
        assert err == "", err
        returncode, error = tasks.destroy_segment(self.master, "%s-to-%s" % replicas)
        assert returncode == 0, error


@pytest.mark.skipif(config.domain_level == 0, reason=reasoning)
class TestCASpecificRUVs(IntegrationTest):
    num_replicas = 2
    topology = 'star'
    username = 'testuser'
    user_firstname = 'test'
    user_lastname = 'user'

    def test_delete_ruvs(self):
        """
        http://www.freeipa.org/page/V4/Manage_replication_topology_4_4/
        Test_Plan#Test_case:_clean-ruv_subcommand
        """
        replica = self.replicas[0]
        master = self.master
        res1 = master.run_command(['ipa-replica-manage', 'list-ruv', '-p',
                                  master.config.dirman_password])
        assert(res1.stdout_text.count(replica.hostname) == 2 and
               "Certificate Server Replica"
               " Update Vectors" in res1.stdout_text), (
               "CA-specific RUVs are not displayed")
        ruvid_re = re.compile(".*%s:389: (\d+).*" % replica.hostname)
        replica_ruvs = ruvid_re.findall(res1.stdout_text)
        # Find out the number of RUVids
        assert(len(replica_ruvs) == 2), (
            "The output should display 2 RUV ids of the selected replica")

        # Block replication to preserve replica-specific RUVs
        dashed_domain = master.domain.realm.replace(".", '-')
        dirsrv_service = "dirsrv@%s.service" % dashed_domain
        replica.run_command(['systemctl', 'stop', dirsrv_service])
        try:
            master.run_command(['ipa-replica-manage', 'clean-ruv',
                                replica_ruvs[1], '-p',
                                master.config.dirman_password, '-f'])
            res2 = master.run_command(['ipa-replica-manage',
                                       'list-ruv', '-p',
                                       master.config.dirman_password])

            assert(res2.stdout_text.count(replica.hostname) == 1), (
                "CA RUV of the replica is still displayed")
            master.run_command(['ipa-replica-manage', 'clean-ruv',
                                replica_ruvs[0], '-p',
                                master.config.dirman_password, '-f'])
            res3 = master.run_command(['ipa-replica-manage', 'list-ruv', '-p',
                                       master.config.dirman_password])
            assert(replica.hostname not in res3.stdout_text), (
                "replica's RUV is still displayed")
        finally:
            replica.run_command(['systemctl', 'start', dirsrv_service])

    def test_replica_uninstall_deletes_ruvs(self):
        """
        http://www.freeipa.org/page/V4/Manage_replication_topology_4_4/Test_Plan
        #Test_case:_.2A-ruv_subcommands_of_ipa-replica-manage_are_extended
        _to_handle_CA-specific_RUVs
        """
        master = self.master
        replica = self.replicas[1]
        res1 = master.run_command(['ipa-replica-manage', 'list-ruv', '-p',
                                  master.config.dirman_password]).stdout_text
        assert(res1.count(replica.hostname) == 2), (
            "Did not find proper number of replica hostname (%s) occurrencies"
            " in the command output: %s" % (replica.hostname, res1))

        master.run_command(['ipa-replica-manage', 'del', replica.hostname,
                            '-p', master.config.dirman_password])
        tasks.uninstall_master(replica)
        res2 = master.run_command(['ipa-replica-manage', 'list-ruv', '-p',
                                  master.config.dirman_password]).stdout_text
        assert(replica.hostname not in res2), (
            "Replica RUVs were not clean during replica uninstallation")


@pytest.mark.xfail(reason="Ticket N 7622", strict=True)
class TestReplicaManageDel(IntegrationTest):
    domain_level = 0
    topology = 'star'
    num_replicas = 3

    def test_replica_managed_del_domlevel0(self):
        """
        http://www.freeipa.org/page/V4/Manage_replication_topology_4_4/
        Test_Plan#Test_case:_ipa-replica-manage_del_with_turned_off_replica
        _under_domain_level_0_keeps_ca-related_RUVs
        """
        master = self.master
        replica = self.replicas[0]
        replica.run_command(['ipactl', 'stop'])
        master.run_command(['ipa-replica-manage', 'del', '-f', '-p',
                            master.config.dirman_password, replica.hostname])
        result = master.run_command(['ipa-replica-manage', 'list-ruv',
                                     '-p', master.config.dirman_password])
        num_ruvs = result.stdout_text.count(replica.hostname)
        assert(num_ruvs == 1), ("Expected to find 1 replica's RUV, found %s" %
                                num_ruvs)
        ruvid_re = re.compile(".*%s:389: (\d+).*" % replica.hostname)
        replica_ruvs = ruvid_re.findall(result.stdout_text)
        master.run_command(['ipa-replica-manage', 'clean-ruv', '-f',
                            '-p', master.config.dirman_password,
                            replica_ruvs[0]])
        result2 = master.run_command(['ipa-replica-manage', 'list-ruv',
                                      '-p', master.config.dirman_password])
        assert(replica.hostname not in result2.stdout_text), (
            "Replica's RUV was not properly removed")

    def test_clean_dangling_ruv_multi_ca(self):
        """
        http://www.freeipa.org/page/V4/Manage_replication_topology_4_4/
        Test_Plan#Test_case:_ipa-replica-manage_clean-dangling-ruv_in_a
        _multi-CA_setup
        """
        master = self.master
        replica = self.replicas[1]
        replica.run_command(['ipa-server-install', '--uninstall', '-U'])
        master.run_command(['ipa-replica-manage', 'del', '-f', '-p',
                            master.config.dirman_password, replica.hostname])
        result1 = master.run_command(['ipa-replica-manage', 'list-ruv', '-p',
                                      master.config.dirman_password])
        ruvid_re = re.compile(".*%s:389: (\d+).*" % replica.hostname)
        assert(ruvid_re.search(result1.stdout_text)), (
            "Replica's RUV should not be removed under domain level 0")
        master.run_command(['ipa-replica-manage', 'clean-dangling-ruv', '-p',
                            master.config.dirman_password], stdin_text="yes\n")
        result2 = master.run_command(['ipa-replica-manage', 'list-ruv', '-p',
                                      master.config.dirman_password])
        assert(replica.hostname not in result2.stdout_text), (
            "Replica's RUV was not removed by a clean-dangling-ruv command")

    def test_replica_managed_del_domlevel1(self):
        """
        http://www.freeipa.org/page/V4/Manage_replication_topology_4_4/
        Test_Plan#Test_case:_ipa-replica-manage_del_with_turned_off_replica
        _under_domain_level_1_removes_ca-related_RUVs
        """
        master = self.master
        replica = self.replicas[2]
        master.run_command(['ipa', 'domainlevel-set', '1'])
        replica.run_command(['ipactl', 'stop'])
        master.run_command(['ipa-replica-manage', 'del', '-f', '-p',
                            master.config.dirman_password, replica.hostname])
        result = master.run_command(['ipa-replica-manage', 'list-ruv',
                                     '-p', master.config.dirman_password])
        assert(replica.hostname not in result.stdout_text), (
            "Replica's RUV was not properly removed")
