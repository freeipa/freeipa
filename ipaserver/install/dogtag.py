#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
Dogtag-based service installer module
"""

from ipalib.install import service
from ipalib.install.service import prepare_only, replica_install_only
from ipapython.install.core import knob


class DogtagInstallInterface(service.ServiceInstallInterface):
    """
    Interface common to all Dogtag-based service installers
    """

    ca_file = knob(
        str, None,
        description="location of CA PKCS#12 file",
        cli_metavar='FILE',
    )
    ca_file = prepare_only(ca_file)
    ca_file = replica_install_only(ca_file)
