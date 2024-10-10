from __future__ import absolute_import

import os
import textwrap
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

umockdevrun = textwrap.dedent("""
#!/usr/bin/expect -f
spawn umockdev-run --device {device} --ioctl /dev/hidraw1={ioctl} --script /dev/hidraw1={script} -- {command}   # noqa: E501
expect "Enter PIN:"
send -- "{pin}\\r"
expect Shell>
""")


def setup_umockdev(host):
    tasks.install_packages(host, ['wget', 'umockdev', 'expect'])
    randomc_path = setup_files_on_host(host, file='random.c')
    host.run_command(["cat", randomc_path])
    host.run_command(["yum", "install", "gcc", "openssl-devel", "-y"])
    host.run_command(["gcc", "-fPIC", "-shared", "-o", "/opt/random.so",
                      randomc_path, "-lcrypto"]
                     )
    BASHRC_CFG = "/root/.bashrc"
    host.run_command('echo "export HIDRAW=/dev/hidraw1" >> ' + BASHRC_CFG)
    host.run_command('echo "export LD_PRELOAD=/opt/random.so" >> ' + BASHRC_CFG)  # noqa: E501
    host.run_command('echo "$HIDRAW"')
    host.run_command('echo "$LD_PRELOAD"')
    host.run_command('bash')


def setup_files_on_host(host, file):
    dest = "test_integration/data/{0}".format(file)
    here = os.path.dirname(os.path.realpath('__file__'))
    with open(os.path.join(here, dest),'rb') as f:
        contents = f.read()
    path = "/opt/{0}".format(file)
    host.put_file_contents(path, contents)
    return path


class TestPasskey(IntegrationTest):

    num_clients = 1

    @classmethod
    def install(cls, mh):
        setup_umockdev(cls.clients[0])
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_passkey_register_ipa_user(self):
        """
        Test case to check that register ipa user with invalid/valid pin
        """
        client = self.clients[0]

        user = "test2"
        tasks.user_add(self.master, user, extra_args=["--user-auth-type=passkey"])  # noqa: E501

        setup_files_on_host(client, file='passkey_hidraw1.device')
        setup_files_on_host(client, file='passkey_test2hidraw1.ioctl')
        setup_files_on_host(client, file='passkey_test2hidraw1.script')

        cred = "obibdu8+xE2O/D+cfzl0xD4IqXZeGSmWciJJfRRlhJOs+MS22CZpPfDmC5H5DO5Ic8zE4QXHz9CFPh+RQh8Z1Q=="  # noqa: E501
        register = 'ipa user-add-passkey test2 --register --cose-type=es256 --require-user-verification=True'  # noqa: E501
        contents = umockdevrun.format(
            device='/opt/passkey_hidraw1.device',
            ioctl='/opt/passkey_test2hidraw1.ioctl',
            script='/opt/passkey_test2hidraw1.script',
            command=register,
            pin='12345'
        )
        client.put_file_contents("/tmp/login.exp", contents)
        client.run_command(['expect', '/tmp/login.exp'])
        test = client.run_command(['ipa', 'user-show', user])
        assert cred in test.stdout_text
