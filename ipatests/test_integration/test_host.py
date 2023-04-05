from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestHost(IntegrationTest):

    topology = 'line'

    def check_host_contains_attribute(self, host, expected):
        """
        Helper function to test if host contains expected attribute, using both
        ipa host-show and ldapsearch.
        """
        host_show_result = host.run_command(["ipa host-show", host, "--all"])
        assert expected in host_show_result.stdout_text
        ldapsearch_result = host.run_command(["ldapsearch -h", host])
        assert expected in ldapsearch_result.stdout_text

    def test_host_operations_with_option_macaddress(self):
        """
        Several tests of ipa host-mod and ipa host-add with defferent options,
        working with macaddress and ip address.
        """

        host = self.master
        # chosen random MAC address for test
        host_macaddr = u'00:50:56:30:F6:5F'
        tasks.kinit_admin(host)

        try:
            # addattr with option macaddress
            host.run_command(["ipa host-mod --addattr macaddress=",
                              host_macaddr, host.hostname])

            self.check_host_contains_attribute(host, host_macaddr)

            # delattr with option macaddress with incorrect value
            incorrect_host_macaddress = u'00:50:56:30:F6:EE'
            result_incorrect_mac = host.run_command(
                ["ipa host-mod --delattr macaddress=",
                 incorrect_host_macaddress, host],
                raiseonerr=False
            )
            assert result_incorrect_mac.returncode != 0

            # delattr with option macaddress
            host.run_command(["ipa host-mod --delattr macaddress=",
                              host_macaddr, host])

            host_show_result = host.run_command(["ipa host-show", host,
                                                 "--all"])
            assert host_macaddr not in host_show_result.stdout_text
            ldapsearch_result = host.run_command(["ldapsearch -h", host])
            assert host_macaddr not in ldapsearch_result.stdout_text

            # setattr with option macaddress
            host.run_command(["ipa host-mod --setattr macaddress=",
                              host_macaddr, host])

            self.check_host_contains_attribute(host, host_macaddr)

            # setattr with option macaddress and addattr on macaddress
            # shouldn't be multivalue - additional add should fail
            result = host.run_command(["ipa host-mod --addattr macaddress=",
                                       host_macaddr, host])
            assert result.returncode != 0

            # delattr with option macaddress with lowercase
            host_macaddr_lowercase = host_macaddr.lower()
            host.run_command(["ipa host-mod --delattr macaddress=",
                              host_macaddr_lowercase, host])

            # add a host with options macaddress and force
            host.run_command(["ipa host-add", host, "--macaddress=",
                              host_macaddr, "--force"])

            self.check_host_contains_attribute(host, host_macaddr)

            # hostmod of a host with option macaddress
            modified_macaddr = ":".join(host_macaddr.split(":")[:-1]) + ":EE"
            host.run_command(["ipa host-mod --macaddress=",
                              modified_macaddr, host])

            self.check_host_contains_attribute(host, modified_macaddr)
        finally:
            host.run_command(["ipa host-del", host.hostname])

    def test_add_host_with_macaddr_and_dns_record(self):
        """
        Test of adding host with specific ip address using ipa host-add
        and respective DNS record.
        """

        host = self.master

        # chosen random MAC and IP address for test
        host_macaddr = u'00:50:56:30:F6:5F'
        host_ipaddr = u'192.168.100.4'
        tasks.kinit_admin(host)

        # Add host with option macaddress and DNS Record
        host.run_command(["ipa host-add --macaddress=", host_macaddr,
                          "--ip-address=", host_ipaddr, host])

        result = host.run_command(["ipa dnsrecord-show",
                                   f'{host.domain.name}.', host])
        assert host_ipaddr in result.stdout_text

        self.check_host_contains_attribute(host, host_macaddr)
