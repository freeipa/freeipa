#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""RHEL container tasks
"""
import logging

from ipaplatform.rhel.tasks import RHELTaskNamespace


logger = logging.getLogger(__name__)


class RHELContainerTaskNamespace(RHELTaskNamespace):
    def modify_nsswitch_pam_stack(
        self, sssd, mkhomedir, statestore, sudo=True
    ):
        # freeipa-container images are preconfigured
        # authselect select sssd with-sudo --force
        logger.debug("Authselect is pre-configured in container images.")

    def is_mkhomedir_supported(self):
        # authselect is not pre-configured with mkhomedir
        return False

    def restore_auth_configuration(self, path):
        # backup is supported but restore is a no-op
        logger.debug("Authselect is pre-configured in container images.")

    def migrate_auth_configuration(self, statestore):
        logger.debug("Authselect is pre-configured in container images.")


tasks = RHELContainerTaskNamespace()
