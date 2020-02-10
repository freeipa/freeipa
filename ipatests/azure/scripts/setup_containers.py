import logging
import os
import subprocess

import docker
from jinja2 import Template

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

IPA_TESTS_ENV_WORKING_DIR = os.environ.get('IPA_TESTS_ENV_WORKING_DIR')
IPA_TESTS_ENV_NAME = os.environ.get('IPA_TESTS_ENV_NAME')
IPA_TESTS_ENV_ID = os.environ.get('IPA_TESTS_ENV_ID', '1')
IPA_TESTS_CLIENTS = int(os.environ.get('IPA_TESTS_CLIENTS', 0))
IPA_TESTS_REPLICAS = int(os.environ.get('IPA_TESTS_REPLICAS', 0))
IPA_TESTS_DOMAIN = os.environ.get('IPA_TESTS_DOMAIN', 'ipa.test')
IPA_SSH_PRIV_KEY = os.environ.get('IPA_SSH_PRIV_KEY', '/root/.ssh/id_rsa')
IPA_DNS_FORWARDER = os.environ.get('IPA_DNS_FORWARDER', '8.8.8.8')
IPA_NETWORK = os.environ.get('IPA_NETWORK', 'ipanet')
IPA_CONTROLLER_TYPE = os.environ.get('IPA_CONTROLLER_TYPE', 'master')
IPA_TEST_CONFIG_TEMPLATE = os.environ.get(
    'IPA_TEST_CONFIG_TEMPLATE', './templates/ipa-test-config-template.yaml')

IPA_TESTS_ENV_DIR = os.path.join(IPA_TESTS_ENV_WORKING_DIR, IPA_TESTS_ENV_NAME)
IPA_TEST_CONFIG = "ipa-test-config.yaml"


class Container:
    """
    Represents group of Docker container
    """
    def __init__(self, role, dns=IPA_DNS_FORWARDER, num=1,
                 prefix=IPA_TESTS_ENV_ID, domain=IPA_TESTS_DOMAIN):
        self.role = role
        self.num = num
        self.prefix = prefix
        self.dns = dns
        self.domain = domain
        self.dclient = docker.from_env()

    @property
    def hostnames(self):
        """
        hostnames of containers within group
        """
        if not hasattr(self, '_hostnames'):
            self._hostnames = ['{}{}.{}'.format(self.role, c, self.domain)
                               for c in range(1, self.num + 1)]
        return self._hostnames

    @property
    def names(self):
        """
        names of containers within group
        """
        if not hasattr(self, '_names'):
            self._names = ['{}_{}_{}'.format(self.prefix, self.role, c)
                           for c in range(1, self.num + 1)]
        return self._names

    def ip(self, name):
        """
        ipv4 address of container
        """
        ipanet = '{}_{}'.format(IPA_TESTS_ENV_ID, IPA_NETWORK)
        dcont = self.dclient.containers.get(name)
        return dcont.attrs['NetworkSettings']['Networks'][ipanet]['IPAddress']

    @property
    def ips(self):
        """
        ipv4 addresses of containers within group
        """
        if not hasattr(self, '_ips'):
            self._ips = [self.ip(n) for n in self.names]
        return self._ips

    def umount_docker_resource(self, path):
        """
        Umount resource by its path
        """
        cmd = [
            "/bin/umount", path
        ]
        self.execute_all(cmd)

        cmd = [
            "/bin/chmod",
            "a-x",
            path,
        ]
        self.execute_all(cmd)

    def execute(self, name, args):
        """
        Exec an arbitrary command within container
        """
        dcont = self.dclient.containers.get(name)
        logging.info("%s: run: %s", dcont.name, args)
        result = dcont.exec_run(args, demux=True)
        if result.output[0] is not None:
            logging.info("%s: %s", dcont.name, result.output[0])
        logging.info("%s: result: %s", dcont.name, result.exit_code)
        if result.exit_code:
            logging.error("stderr: %s", result.output[1].decode())
            raise subprocess.CalledProcessError(
                result.exit_code, args,
                result.output[1]
            )
        return result

    def execute_all(self, args):
        """
        Exec an arbitrary command within every container of group
        """
        results = []
        for n in self.names:
            results.append(self.execute(n, args))
        return results

    def add_ssh_pubkey(self, key):
        """
        Add ssh public key into every container of group
        """
        home_ssh_dir = "/root/.ssh"
        auth_keys = os.path.join(home_ssh_dir, "authorized_keys")
        cmd = [
            "/bin/bash", "-c",
            (f"mkdir {home_ssh_dir} "
             f"; chmod 0700 {home_ssh_dir} "
             f"&& touch {auth_keys} "
             f"&& chmod 0600 {auth_keys} "
             f"&& echo {key} >> {auth_keys}"
             )
        ]
        self.execute_all(cmd)

    def setup_hosts(self):
        """
        Overwrite hosts within every container of group
        """
        self.umount_docker_resource("/etc/hosts")
        for n, i, h in zip(self.names, self.ips, self.hostnames):
            hosts = "127.0.0.1 localhost\n::1 localhost\n{ip} {host}".format(
                ip=i, host=h,
            )
            cmd = [
                "/bin/bash", "-c",
                "echo -e '{hosts}' > /etc/hosts".format(hosts=hosts),
            ]
            self.execute(name=n, args=cmd)

    def setup_hostname(self):
        self.umount_docker_resource("/etc/hostname")
        for n, h in zip(self.names, self.hostnames):
            cmd = [
                "/bin/bash", "-c",
                "echo -e '{hostname}' > /etc/hostname".format(hostname=h),
            ]
            self.execute(name=n, args=cmd)

            cmd = [
                "hostnamectl",
                "set-hostname", h,
            ]
            self.execute(name=n, args=cmd)

    def setup_resolvconf(self):
        """
        Overwrite resolv conf within every container of group
        """
        self.umount_docker_resource("/etc/resolv.conf")
        ns = "nameserver {dns}".format(dns=self.dns)
        cmd = [
            "/bin/bash", "-c",
            "echo {ns} > /etc/resolv.conf".format(ns=ns),
        ]
        self.execute_all(cmd)


class Controller(Container):
    """
    Manages groups of containers
    """
    def __init__(self, contr_type=IPA_CONTROLLER_TYPE):
        self.containers = []
        self.contr_type = contr_type
        if self.contr_type == 'master':
            self.master = None

    def append(self, container):
        self.containers.append(container)

    def setup_ssh(self):
        """
        Generate ssh key pair and copy public part to all containers
        """
        cmd = ["rm", "-f", IPA_SSH_PRIV_KEY]
        self.execute(args=cmd)

        cmd = [
            "ssh-keygen", "-q",
            "-f", IPA_SSH_PRIV_KEY,
            "-t", "rsa",
            "-m", "PEM",
            "-N", "",
        ]
        self.execute(args=cmd)

        cmd = ["/bin/bash", "-c", "cat {}.pub".format(IPA_SSH_PRIV_KEY)]
        key = self.execute(cmd).output[0].decode().rstrip()
        for container in self.containers:
            container.add_ssh_pubkey(key)

    def execute(self, args):
        """
        Execute a command on controller (either master or local machine)
        """
        if self.contr_type == 'master':
            if self.master is None:
                for container in self.containers:
                    if container.role == "master":
                        self.master = container
                        break
            return self.master.execute(name=master.names[0], args=args)

        proc = subprocess.run(args, check=True, capture_output=True)
        return [proc.stdout.decode().rstrip().strip("'")]

    def setup_hosts(self):
        """
        Overwrite Docker's hosts
        """
        hosts = []
        for container in self.containers:
            container.setup_hosts()
            for i, h in zip(container.ips, container.hostnames):
                hosts.append("{} {}".format(i, h))

        cmd = [
            "/bin/bash", "-c",
            "echo -e '{hosts}' >> /etc/hosts".format(hosts='\n'.join(hosts)),
        ]
        self.execute(cmd)

    def setup_hostname(self):
        """
        Overwrite Docker's hostname
        """
        for container in self.containers:
            container.setup_hostname()

    def setup_resolvconf(self):
        """
        Overwrite Docker's embedded DNS ns
        """
        for container in self.containers:
            container.setup_resolvconf()

    def generate_ipa_test_config(self, config):
        with open(IPA_TEST_CONFIG_TEMPLATE, 'r') as f:
            # assert foobar
            template = Template(f.read(), trim_blocks=True, lstrip_blocks=True)

        print(template.render(config))

        with open(os.path.join(IPA_TESTS_ENV_DIR, IPA_TEST_CONFIG), 'w') as f:
            f.write(template.render(config))


controller = Controller()
master = Container(role='master')
clients = Container(role='client', num=IPA_TESTS_CLIENTS, dns=master.ips[0])
replicas = Container(role='replica', num=IPA_TESTS_REPLICAS, dns=master.ips[0])

controller.append(master)
controller.append(clients)
controller.append(replicas)

controller.setup_ssh()
controller.setup_hosts()
controller.setup_hostname()
controller.setup_resolvconf()

config = {
    'dns_forwarder': IPA_DNS_FORWARDER,
    'ssh_private_key': IPA_SSH_PRIV_KEY,
    'domain_name': IPA_TESTS_DOMAIN,
    'master': master.ips,
    'replicas': replicas.ips,
    'clients': clients.ips,
}
controller.generate_ipa_test_config(config)
