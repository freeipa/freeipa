#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
Connection check module
"""

from ipalib.install import service
from ipalib.install.service import enroll_only, replica_install_only
from ipapython.install.core import knob


class ConnCheckInterface(service.ServiceAdminInstallInterface):
    """
    Interface common to all installers which perform connection check to the
    remote master.
    """

    skip_conncheck = knob(
        None,
        description="skip connection check to remote master",
    )
    skip_conncheck = enroll_only(skip_conncheck)
    skip_conncheck = replica_install_only(skip_conncheck)
