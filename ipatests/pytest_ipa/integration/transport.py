#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Enhanced SSH transport for pytest multihost

Provides SSH password login for OpenSSH transport
"""
import os

from pytest_multihost.transport import OpenSSHTransport


class IPAOpenSSHTransport(OpenSSHTransport):
    def _get_ssh_argv(self):
        """Return the path to SSH and options needed for every call"""
        control_file = os.path.join(self.control_dir.path, "control")
        known_hosts_file = os.path.join(self.control_dir.path, "known_hosts")

        argv = [
            "ssh",
            "-l",
            self.host.ssh_username,
            "-o",
            "ControlPath=%s" % control_file,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=%s" % known_hosts_file,
        ]

        if self.host.ssh_key_filename:
            key_filename = os.path.expanduser(self.host.ssh_key_filename)
            argv.extend(["-i", key_filename])
        elif self.host.ssh_password:
            password_file = os.path.join(self.control_dir.path, "password")
            with open(password_file, "w") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(self.host.ssh_password)
                f.write("\n")
            argv = ["sshpass", f"-f{password_file}"] + argv
        else:
            self.log.critical("No SSH credentials configured")
            raise RuntimeError("No SSH credentials configured")

        argv.append(self.host.external_hostname)
        self.log.debug("SSH invocation: %s", argv)

        return argv
