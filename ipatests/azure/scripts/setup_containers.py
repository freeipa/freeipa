import logging
import os
import subprocess

import docker
from jinja2 import Template

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

IPA_TESTS_ENV_WORKING_DIR = os.environ.get("IPA_TESTS_ENV_WORKING_DIR")
IPA_TESTS_ENV_NAME = os.environ.get("IPA_TESTS_ENV_NAME")
IPA_TESTS_ENV_ID = os.environ.get("IPA_TESTS_ENV_ID", "1")
IPA_TESTS_CLIENTS = int(os.environ.get("IPA_TESTS_CLIENTS", 0))
IPA_TESTS_REPLICAS = int(os.environ.get("IPA_TESTS_REPLICAS", 0))
IPA_TESTS_DOMAIN = os.environ.get("IPA_TESTS_DOMAIN", "ipa.test")
IPA_SSH_PRIV_KEY = os.environ.get("IPA_SSH_PRIV_KEY", "/root/.ssh/id_rsa")
IPA_DNS_FORWARDER = os.environ.get("IPA_DNS_FORWARDER", "8.8.8.8")
IPA_NETWORK = os.environ.get("IPA_NETWORK", "ipanet")
IPA_CONTROLLER_TYPE = os.environ.get("IPA_CONTROLLER_TYPE", "master")
IPA_TEST_CONFIG_TEMPLATE = os.environ.get(
    "IPA_TEST_CONFIG_TEMPLATE", "./templates/ipa-test-config-template.yaml"
)

IPA_TESTS_ENV_DIR = os.path.join(IPA_TESTS_ENV_WORKING_DIR, IPA_TESTS_ENV_NAME)
IPA_TEST_CONFIG = "ipa-test-config.yaml"


class Container:
    """
    Represents Docker container
    """

    def __init__(self, name, hostname, network):
        self.name = name
        self.hostname = hostname
        self.network = network
        self.dclient = docker.from_env()

    @property
    def ip(self):
        """
        ipv4 address of container
        """
        if not hasattr(self, "_ip"):
            dcont = self.dclient.containers.get(self.name)
            self._ip = dcont.attrs["NetworkSettings"]["Networks"][
                self.network
            ]["IPAddress"]

        return self._ip

    @property
    def ipv6(self):
        """
        ipv6 address of container
        """
        if not hasattr(self, "_ipv6"):
            dcont = self.dclient.containers.get(self.name)
            self._ipv6 = dcont.attrs["NetworkSettings"]["Networks"][
                self.network
            ]["GlobalIPv6Address"]

        return self._ipv6

    def execute(self, args):
        """
        Exec an arbitrary command within container
        """
        dcont = self.dclient.containers.get(self.name)
        logging.info("%s: run: %s", dcont.name, args)
        result = dcont.exec_run(args, demux=True)
        if result.output[0] is not None:
            logging.info("%s: %s", dcont.name, result.output[0])
        logging.info("%s: result: %s", dcont.name, result.exit_code)
        if result.exit_code:
            logging.error("stderr: %s", result.output[1].decode())
            raise subprocess.CalledProcessError(
                result.exit_code, args, result.output[1]
            )
        return result


class ContainersGroup:
    """
    Represents group of Docker containers
    """

    HOME_SSH_DIR = "/root/.ssh"

    def __init__(
        self,
        role,
        nameservers=[IPA_DNS_FORWARDER],
        scale=1,
        prefix=IPA_TESTS_ENV_ID,
        domain=IPA_TESTS_DOMAIN,
    ):
        self.role = role
        self.scale = scale
        self.prefix = prefix
        self.nameservers = nameservers
        self.domain = domain

        # initialize containers
        self.containers = [
            Container(
                name=f"{self.prefix}_{self.role}_{c}",
                hostname=f"{self.role}{c}.{self.domain}",
                network=f"{IPA_TESTS_ENV_ID}_{IPA_NETWORK}",
            )
            for c in range(1, self.scale + 1)
        ]

    def execute_all(self, args):
        """
        Sequentially exec an arbitrary command within every container of group
        """
        results = []
        for cont in self.containers:
            results.append(cont.execute(args))
        return results

    def ips(self):
        return [cont.ip for cont in self.containers]

    def umount_docker_resource(self, path):
        """
        Umount resource by its path
        """
        cmd = ["/bin/umount", path]
        self.execute_all(cmd)

        cmd = [
            "/bin/chmod",
            "a-x",
            path,
        ]
        self.execute_all(cmd)

    def add_ssh_pubkey(self, key):
        """
        Add ssh public key into every container of group
        """
        auth_keys = os.path.join(self.HOME_SSH_DIR, "authorized_keys")
        cmd = [
            "/bin/bash",
            "-c",
            (
                f"mkdir {self.HOME_SSH_DIR} "
                f"; chmod 0700 {self.HOME_SSH_DIR} "
                f"&& touch {auth_keys} "
                f"&& chmod 0600 {auth_keys} "
                f"&& echo {key} >> {auth_keys}"
            ),
        ]
        self.execute_all(cmd)

    def setup_hosts(self):
        """
        Overwrite hosts within every container of group
        """
        self.umount_docker_resource("/etc/hosts")
        for cont in self.containers:
            hosts = "\n".join(
                [
                    "127.0.0.1 localhost",
                    "::1 localhost",
                    f"{cont.ip} {cont.hostname}",
                    f"{cont.ipv6} {cont.hostname}",
                ]
            )
            cmd = ["/bin/bash", "-c", f"echo -e '{hosts}' > /etc/hosts"]
            cont.execute(cmd)

    def setup_hostname(self):
        self.umount_docker_resource("/etc/hostname")
        for cont in self.containers:
            cmd = [
                "/bin/bash",
                "-c",
                f"echo -e '{cont.hostname}' > /etc/hostname",
            ]
            cont.execute(cmd)

            cmd = ["hostnamectl", "set-hostname", cont.hostname]
            cont.execute(cmd)

    def setup_resolvconf(self):
        """
        Overwrite resolv conf within every container of group
        """
        self.umount_docker_resource("/etc/resolv.conf")
        nameservers = "\n".join(
            [f"nameserver {ns}" for ns in self.nameservers]
        )
        cmd = [
            "/bin/bash",
            "-c",
            f"echo -e '{nameservers}' > /etc/resolv.conf",
        ]
        self.execute_all(cmd)

    def ignore_service_in_container(self, service):
        """
        Amend systemd service configuration to be ignored in a container
        """
        service_dir = os.path.join(
            "/etc/systemd/system", "{}.service.d".format(service)
        )
        override_file = os.path.join(service_dir, "ipa-override.conf")
        cmds = [
            "/bin/bash",
            "-c",
            (
                f"mkdir -p {service_dir};"
                f"echo '[Unit]' > {override_file};"
                f"echo 'ConditionVirtualization=!container' >> {override_file}"
            ),
        ]
        self.execute_all(cmds)

    def setup_container_overrides(self):
        """
        Set services known to not work in containers to be ignored
        """
        for service in [
            "nis-domainname",
            "chronyd",
        ]:
            self.ignore_service_in_container(service)

        self.execute_all(["systemctl", "daemon-reload"])


class Controller(Container):
    """
    Represents Controller, which manages groups of containers groups
    """

    def __init__(self, contr_type=IPA_CONTROLLER_TYPE):
        self.containers_groups = []
        self.contr_type = contr_type

    def append(self, containers_group):
        self.containers_groups.append(containers_group)

    def setup_ssh(self):
        """
        Generate ssh key pair and copy public part to all containers
        """
        cmd = ["rm", "-f", IPA_SSH_PRIV_KEY]
        self.execute(cmd)

        cmd = [
            "ssh-keygen",
            "-q",
            "-f",
            IPA_SSH_PRIV_KEY,
            "-t",
            "rsa",
            "-m",
            "PEM",
            "-N",
            "",
        ]
        self.execute(cmd)

        cmd = ["/bin/bash", "-c", "cat {}.pub".format(IPA_SSH_PRIV_KEY)]
        key = self.execute(cmd).output[0].decode().rstrip()
        for containers_group in self.containers_groups:
            containers_group.add_ssh_pubkey(key)

    @property
    def master_container(self):
        if not hasattr(self, "_master_container"):
            master_containers_group = None
            for containers_group in self.containers_groups:
                if containers_group.role == "master":
                    master_containers_group = containers_group
                    break
            if master_containers_group is None:
                raise ValueError(
                    "There must be container group with master role"
                )
            # assume the only master
            self._master_container = master_containers_group.containers[0]

        return self._master_container

    def execute(self, args):
        """
        Execute a command on controller (either master or local machine)
        """
        if self.contr_type != "master":
            proc = subprocess.run(args, check=True, capture_output=True)
            return [proc.stdout.decode().rstrip().strip("'")]

        return self.master_container.execute(args)

    def setup_hosts(self):
        """
        Overwrite Docker's hosts
        """
        hosts = []
        for containers_group in self.containers_groups:
            containers_group.setup_hosts()
            # prevent duplication of master entries
            if (
                self.contr_type == "master"
                and containers_group.role == "master"
            ):
                continue

            for container in containers_group.containers:
                hosts.append(f"{container.ip} {container.hostname}")
                hosts.append(f"{container.ipv6} {container.hostname}")

        cmd = [
            "/bin/bash",
            "-c",
            "echo -e '{hosts}' >> /etc/hosts".format(hosts="\n".join(hosts)),
        ]
        self.execute(cmd)

    def setup_hostname(self):
        """
        Overwrite Docker's hostname
        """
        for containers_group in self.containers_groups:
            containers_group.setup_hostname()

    def setup_resolvconf(self):
        """
        Overwrite Docker's embedded DNS ns
        """
        for containers_group in self.containers_groups:
            containers_group.setup_resolvconf()

    def generate_ipa_test_config(self, config):
        with open(IPA_TEST_CONFIG_TEMPLATE, "r") as f:
            template = Template(f.read(), trim_blocks=True, lstrip_blocks=True)

        logging.info(template.render(config))

        with open(os.path.join(IPA_TESTS_ENV_DIR, IPA_TEST_CONFIG), "w") as f:
            f.write(template.render(config))

    def setup_container_overrides(self):
        """
        Override services known to not work in containers
        """
        for containers_group in self.containers_groups:
            containers_group.setup_container_overrides()


controller = Controller()
master = ContainersGroup(role="master")

# assume the only master
master_ips = [master.containers[0].ip, master.containers[0].ipv6]
clients = ContainersGroup(
    role="client", scale=IPA_TESTS_CLIENTS, nameservers=master_ips
)
replicas = ContainersGroup(
    role="replica", scale=IPA_TESTS_REPLICAS, nameservers=master_ips
)

controller.append(master)
controller.append(clients)
controller.append(replicas)

controller.setup_ssh()
controller.setup_hosts()
controller.setup_hostname()
controller.setup_resolvconf()
controller.setup_container_overrides()

config = {
    "dns_forwarder": IPA_DNS_FORWARDER,
    "ssh_private_key": IPA_SSH_PRIV_KEY,
    "domain_name": IPA_TESTS_DOMAIN,
    "master": master.ips(),
    "replicas": replicas.ips(),
    "clients": clients.ips(),
}
controller.generate_ipa_test_config(config)
