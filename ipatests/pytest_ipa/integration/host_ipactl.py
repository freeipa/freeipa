#
# Copyright (C) 2022  FreeIPA Contributors. See COPYING for license
#

"""Wrapper for ipactl to be run on remote host"""
from collections import namedtuple


class HostIpactl:
    """Wrapper for ipactl to be run on remote host"""

    def __init__(self, host):
        self.host = host

    def run(self, ipactl_args, **kwargs):
        """Run ipactl with `ipactl_args`"""
        cmd = [self.host.paths.IPACTL]
        cmd.extend(ipactl_args)
        return self.host.run_command(cmd, **kwargs)

    def start(self):
        self.run(["start"])

    def stop(self):
        self.run(["stop"])

    def restart(self):
        self.run(["restart"])

    def status(self):
        res = self.run(["status"], raiseonerr=False)
        IpactlStatus = namedtuple(
            "IpactlStatus", ["code", "stdout", "stderr"]
        )
        return IpactlStatus(res.returncode, res.stdout_text, res.stderr_text)
