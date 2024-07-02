from __future__ import absolute_import

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
    random_so = "https://github.com/amore17/freeipa/raw/passkey-integration/ipatests/test_integration/passkey_data/random.so"  # noqa: E501
    host.run_command(['wget', random_so, '-P', '/opt/'])
    BASHRC_CFG = "/root/.bashrc"
    host.run_command('echo "export HIDRAW=/dev/hidraw1" >> ' + BASHRC_CFG)
    host.run_command('echo "export LD_PRELOAD=/opt/random.so" >> ' + BASHRC_CFG)  # noqa: E501
    host.run_command('echo "$HIDRAW"')
    host.run_command('echo "$LD_PRELOAD"')
    host.run_command('bash')


class TestPasskey(IntegrationTest):

    num_clients = 1

    @classmethod
    def install(cls, mh):
        setup_umockdev(cls.clients[0])
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0], nameservers=None)

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
        device = "https://raw.githubusercontent.com/amore17/freeipa/passkey-integration/ipatests/test_integration/passkey_data/hidraw1.device"  # noqa: E501
        ioctl = "https://raw.githubusercontent.com/amore17/freeipa/passkey-integration/ipatests/test_integration/passkey_data/test2hidraw1.ioctl"  # noqa: E501
        script = "https://raw.githubusercontent.com/amore17/freeipa/passkey-integration/ipatests/test_integration/passkey_data/test2hidraw1.script"  # noqa: E501
        client.run_command(['wget', device, '-P', '/opt/'])
        client.run_command(['wget', ioctl, '-P', '/opt/'])
        client.run_command(['wget', script, '-P', '/opt/'])
        cred = "obibdu8+xE2O/D+cfzl0xD4IqXZeGSmWciJJfRRlhJOs+MS22CZpPfDmC5H5DO5Ic8zE4QXHz9CFPh+RQh8Z1Q=="  # noqa: E501
        register = 'ipa user-add-passkey test2 --register --cose-type=es256 --require-user-verification=True'  # noqa: E501
        contents = umockdevrun.format(device='/opt/hidraw1.device',
                                      ioctl='/opt/test2hidraw1.ioctl',
                                      script='/opt/test2hidraw1.script',
                                      command=register,
                                      pin='12345')
        client.put_file_contents("/tmp/login.exp", contents)
        client.run_command(['expect', '/tmp/login.exp'])
        test = client.run_command(['ipa', 'user-show', user])
        assert cred in test.stdout_text
