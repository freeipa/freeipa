#
# Copyright (C) 2020 FreeIPA Contributors, see COPYING for license
#

"""
This module contains default SUSE OS family-specific implementations of
system tasks.
"""

import logging

from ipaplatform.paths import paths
from ipaplatform.redhat.tasks import RedHatTaskNamespace

logger = logging.getLogger(__name__)


class SuseTaskNamespace(RedHatTaskNamespace):
    def restore_context(self, filepath, force=False):
        pass  # FIXME: Implement after libexec move

    def check_selinux_status(self, restorecon=paths.RESTORECON):
        pass  # FIXME: Implement after libexec move

    def set_nisdomain(self, nisdomain):
        nis_variable = "NETCONFIG_NIS_STATIC_DOMAIN"
        try:
            with open(paths.SYSCONF_NETWORK, "r") as f:
                content = [
                    line
                    for line in f
                    if not line.strip().upper().startswith(nis_variable)
                ]
        except IOError:
            content = []

        content.append("{}={}\n".format(nis_variable, nisdomain))

        with open(paths.SYSCONF_NETWORK, "w") as f:
            f.writelines(content)

    def set_selinux_booleans(self, required_settings, backup_func=None):
        return False  # FIXME: Implement after libexec move


tasks = SuseTaskNamespace()
