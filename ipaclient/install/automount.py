#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
Automount installer module
"""

from ipalib.install import service
from ipalib.install.service import enroll_only
from ipapython.install.core import group, knob


@group
class AutomountInstallInterface(service.ServiceInstallInterface):
    """
    Interface of the automount installer

    Knobs defined here will be available in:
    * ipa-client-install
    * ipa-client-automount
    """
    description = "Automount"

    automount_location = knob(
        str, None,
        description="Automount location",
    )
    automount_location = enroll_only(automount_location)
