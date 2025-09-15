#
# Copyright (C) 2018  FreeIPA Contributors.  See COPYING for license
#

"""Firewall class for integration testing using firewalld"""

import abc

from ipapython import ipautil


class FirewallBase(abc.ABC):
    def __init__(self, host):
        """Initialize with host where firewall changes should be applied"""

    @abc.abstractmethod
    def run(self):
        """Enable and start firewall service"""

    @abc.abstractmethod
    def enable_service(self, service):
        """Enable firewall rules for service"""

    @abc.abstractmethod
    def disable_service(self, service):
        """Disable firewall rules for service"""

    @abc.abstractmethod
    def enable_services(self, services):
        """Enable firewall rules for list of services"""

    @abc.abstractmethod
    def disable_services(self, services):
        """Disable firewall rules for list of services"""

    @abc.abstractmethod
    def passthrough_rule(self, rule, ipv=None):
        """Generic method to get direct passthrough rules to
        rule is an ip[6]tables rule without using the ip[6]tables command.
        The rule will per default be added to the IPv4 and IPv6 firewall.
        If there are IP version specific parts in the rule, please make sure
        that ipv is adapted properly.
        The rule is added to the direct sub chain of the chain that is used
        in the rule"""

    @abc.abstractmethod
    def add_passthrough_rules(self, rules, ipv=None):
        """Add passthough rules to the end of the chain
        rules is a list of ip[6]tables rules, where the first entry of each
        rule is the chain. No --append/-A, --delete/-D should be added before
        the chain name, beacuse these are added by the method.
        If there are IP version specific parts in the rule, please make sure
        that ipv is adapted properly.
        """

    @abc.abstractmethod
    def prepend_passthrough_rules(self, rules, ipv=None):
        """Insert passthough rules starting at position 1 as a block
        rules is a list of ip[6]tables rules, where the first entry of each
        rule is the chain. No --append/-A, --delete/-D should be added before
        the chain name, beacuse these are added by the method.
        If there are IP version specific parts in the rule, please make sure
        that ipv is adapted properly.
        """

    @abc.abstractmethod
    def remove_passthrough_rules(self, rules, ipv=None):
        """Remove passthrough rules
        rules is a list of ip[6]tables rules, where the first entry of each
        rule is the chain. No --append/-A, --delete/-D should be added before
        the chain name, beacuse these are added by the method.
        If there are IP version specific parts in the rule, please make sure
        that ipv is adapted properly.
        """


class NoOpFirewall(FirewallBase):
    """
    no-op firewall is intended for platforms which haven't high level firewall
    backend.
    """
    def run(self):
        pass

    def enable_service(self, service):
        pass

    def disable_service(self, service):
        pass

    def enable_services(self, services):
        pass

    def disable_services(self, services):
        pass

    def passthrough_rule(self, rule, ipv=None):
        pass

    def add_passthrough_rules(self, rules, ipv=None):
        pass

    def prepend_passthrough_rules(self, rules, ipv=None):
        pass

    def remove_passthrough_rules(self, rules, ipv=None):
        pass


class FirewallD(FirewallBase):
    def __init__(self, host):
        """Initialize with host where firewall changes should be applied"""
        self.host = host

    def run(self):
        # Unmask firewalld service
        self.host.run_command(["systemctl", "unmask", "firewalld"])
        # Enable firewalld service
        self.host.run_command(["systemctl", "enable", "firewalld"])
        # Start firewalld service
        self.host.run_command(["systemctl", "start", "firewalld"])

    def _rp_action(self, args):
        """Run-time and permanant firewall action"""
        cmd = ["firewall-cmd"]
        cmd.extend(args)

        # Run-time part
        result = self.host.run_command(cmd, raiseonerr=False)
        if result.returncode not in [0, 11, 12]:
            # Ignore firewalld error codes:
            #   11 is ALREADY_ENABLED
            #   12 is NOT_ENABLED
            raise ipautil.CalledProcessError(result.returncode, cmd,
                                             result.stdout_text,
                                             result.stderr_text)

        # Permanent part
        result = self.host.run_command(cmd + ["--permanent"],
                                       raiseonerr=False)
        if result.returncode not in [0, 11, 12]:
            # Ignore firewalld error codes:
            #   11 is ALREADY_ENABLED
            #   12 is NOT_ENABLED
            raise ipautil.CalledProcessError(result.returncode, cmd,
                                             result.stdout_text,
                                             result.stderr_text)

    def enable_service(self, service):
        """Enable firewall service in firewalld runtime and permanent
        environment"""
        self._rp_action(["--add-service", service])

    def disable_service(self, service):
        """Disable firewall service in firewalld runtime and permanent
        environment"""
        self._rp_action(["--remove-service", service])

    def enable_services(self, services):
        """Enable list of firewall services in firewalld runtime and
        permanent environment"""
        args = []
        for service in services:
            args.extend(["--add-service", service])
        self._rp_action(args)

    def disable_services(self, services):
        """Disable list of firewall services in firewalld runtime and
        permanent environment"""
        args = []
        for service in services:
            args.extend(["--remove-service", service])
        self._rp_action(args)

    def passthrough_rule(self, rule, ipv=None):
        """Generic method to get direct passthrough rules to firewalld
        rule is an ip[6]tables rule without using the ip[6]tables command.
        The rule will per default be added to the IPv4 and IPv6 firewall.
        If there are IP version specific parts in the rule, please make sure
        that ipv is adapted properly.
        The rule is added to the direct sub chain of the chain that is used
        in the rule"""
        if ipv is None:
            ipvs = ["ipv4", "ipv6"]
        else:
            ipvs = [ipv]
        for _ipv in ipvs:
            args = ["firewall-cmd", "--direct", "--passthrough", _ipv] + rule
            self.host.run_command(args)

    def add_passthrough_rules(self, rules, ipv=None):
        """Add passthough rules to the end of the chain
        rules is a list of ip[6]tables rules, where the first entry of each
        rule is the chain. No --append/-A, --delete/-D should be added before
        the chain name, beacuse these are added by the method.
        If there are IP version specific parts in the rule, please make sure
        that ipv is adapted properly.
        """
        for rule in rules:
            self.passthrough_rule(["-A"] + rule, ipv)

    def prepend_passthrough_rules(self, rules, ipv=None):
        """Insert passthough rules starting at position 1 as a block
        rules is a list of ip[6]tables rules, where the first entry of each
        rule is the chain. No --append/-A, --delete/-D should be added before
        the chain name, beacuse these are added by the method.
        If there are IP version specific parts in the rule, please make sure
        that ipv is adapted properly.
        """
        # first rule number in iptables is 1
        for i, rule in enumerate(rules, start=1):
            self.passthrough_rule(["-I", rule[0], str(i)] + rule[1:], ipv)

    def remove_passthrough_rules(self, rules, ipv=None):
        """Remove passthrough rules
        rules is a list of ip[6]tables rules, where the first entry of each
        rule is the chain. No --append/-A, --delete/-D should be added before
        the chain name, beacuse these are added by the method.
        If there are IP version specific parts in the rule, please make sure
        that ipv is adapted properly.
        """
        for rule in rules:
            self.passthrough_rule(["-D"] + rule, ipv)


class Firewall(FirewallBase):
    """
    Depending on the ipaplatform proxy firewall tasks to the actual backend.
    Current supported backends: firewalld and no-op firewall.
    """
    def __init__(self, host):
        """Initialize with host where firewall changes should be applied"""
        # break circular dependency
        from .tasks import get_platform  # pylint: disable=cyclic-import

        self.host = host
        platform = get_platform(host)

        firewalls = {
            'rhel': FirewallD,
            'fedora': FirewallD,
            'debian': FirewallD,
            'ubuntu': FirewallD,
            'altlinux': NoOpFirewall,
        }
        if platform not in firewalls:
            raise ValueError(
                "Platform {} doesn't support Firewall".format(platform))
        self.firewall = firewalls[platform](self.host)
        self.run()

    def run(self):
        self.firewall.run()

    def enable_service(self, service):
        self.firewall.enable_service(service)

    def disable_service(self, service):
        self.firewall.disable_service(service)

    def enable_services(self, services):
        self.firewall.enable_services(services)

    def disable_services(self, services):
        self.firewall.disable_services(services)

    def passthrough_rule(self, rule, ipv=None):
        self.firewall.passthrough_rule(rule, ipv)

    def add_passthrough_rules(self, rules, ipv=None):
        self.firewall.add_passthrough_rules(rules, ipv)

    def prepend_passthrough_rules(self, rules, ipv=None):
        self.firewall.prepend_passthrough_rules(rules, ipv)

    def remove_passthrough_rules(self, rules, ipv=None):
        self.firewall.remove_passthrough_rules(rules, ipv)
