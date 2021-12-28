#
# Copyright (C) 2022  FreeIPA Contributors. See COPYING for license
#

"""Wrapper for systemctl to be run on remote host"""
from collections import namedtuple


class HostSystemctl:
    """Wrapper for systemctl to be run on remote host"""

    def __init__(self, host):
        self.host = host

    def resolve_name(self, unit):
        """Resolve service as IPA's knownservice"""
        name = self.host.knownservices[unit].systemd_name
        if unit == "dirsrv":
            # assume valid template name like dirsrv@.service
            service_name, __, service_suffix = name.partition("@")
            name = "{}@{}{}".format(
                service_name, self.host.ds_serverid, service_suffix
            )

        return name

    def run(self, systemctl_args, *, unit, resolve=True, **kwargs):
        """Run systemctl with `systemctl_args` for `unit`"""
        name = unit

        if resolve and name is not None:
            name = self.resolve_name(unit)

        # build command
        cmd = [self.host.paths.SYSTEMCTL]
        cmd.extend(systemctl_args)
        if name is not None:
            cmd.append(name)

        return self.host.run_command(cmd, **kwargs)

    def start(self, unit, resolve=True):
        self.run(["start"], unit=unit, resolve=resolve)

    def stop(self, unit, resolve=True):
        self.run(["stop"], unit=unit, resolve=resolve)

    def reload(self, unit, resolve=True):
        self.run(["reload"], unit=unit, resolve=resolve)

    def restart(self, unit, resolve=True):
        self.run(["restart"], unit=unit, resolve=resolve)

    def try_restart(self, unit, resolve=True):
        self.run(["try-restart"], unit=unit, resolve=resolve)

    def reload_or_restart(self, unit, resolve=True):
        self.run(["reload-or-restart"], unit=unit, resolve=resolve)

    def try_reload_or_restart(self, unit, resolve=True):
        self.run(
            ["try-reload-or-restart"],
            unit=unit,
            resolve=resolve,
        )

    def is_active(self, unit, resolve=True):
        result = self.run(
            ["is-active"], unit=unit, resolve=resolve, raiseonerr=False
        )
        return result.returncode == 0

    def is_failed(self, unit, resolve=True):
        result = self.run(
            ["is-failed"], unit=unit, resolve=resolve, raiseonerr=False
        )
        return result.returncode == 0

    def enable(self, unit, now=False, resolve=True):
        args = ["enable"]
        if now:
            args.extend(["--now"])

        self.run(args, unit=unit, resolve=resolve)

    def disable(self, unit, now=False, resolve=True):
        args = ["disable"]
        if now:
            args.extend(["--now"])

        self.run(args, unit=unit, resolve=resolve)

    def is_enabled(self, unit, resolve=True):
        result = self.run(
            ["is-enabled"], unit=unit, resolve=resolve, raiseonerr=False
        )
        return result.returncode == 0

    def mask(self, unit, now=False, resolve=True):
        args = ["mask"]
        if now:
            args.extend(["--now"])

        self.run(args, unit=unit, resolve=resolve)

    def unmask(self, unit, resolve=True):
        self.run(["unmask"], unit=unit, resolve=resolve)

    def status(self, unit, resolve=True):
        res = self.run(
            ["status"],
            unit=unit,
            resolve=resolve,
            raiseonerr=False,
        )
        SystemctlStatus = namedtuple(
            "SystemctlStatus", ["code", "stdout", "stderr"]
        )
        return SystemctlStatus(res.returncode, res.stdout_text, res.stderr_text)
