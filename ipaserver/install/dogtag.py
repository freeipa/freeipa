#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
Dogtag-based service installer module
"""
import os

# pylint: disable=import-error
from six.moves.configparser import RawConfigParser
# pylint: enable=import-error


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

    pki_config_override = knob(
        str, None,
        cli_names='--pki-config-override',
        description="Path to ini file with config overrides.",
    )

    @pki_config_override.validator
    def pki_config_override(self, value):
        if value is None:
            return
        if not os.path.isabs(value):
            raise ValueError("must use an absolute path")
        try:
            cfg = RawConfigParser()
            with open(value) as f:
                cfg.readfp(f)  # pylint: disable=deprecated-method
        except Exception as e:
            raise ValueError(
                "Invalid config '{}': {}".format(value, e)
            )
