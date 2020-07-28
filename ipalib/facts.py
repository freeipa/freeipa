#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Facts about the installation
"""

import os
from . import sysrestore
from ipaplatform.paths import paths


def is_ipa_configured():
    """
    Use the state to determine if IPA has been configured.
    """
    sstore = sysrestore.StateFile(paths.SYSRESTORE)
    return sstore.get_state('installation', 'complete')


def is_ipa_client_configured(on_master=False):
    """
    Consider IPA client not installed if nothing is backed up
    and default.conf file does not exist. If on_master is set to True,
    the existence of default.conf file is not taken into consideration,
    since it has been already created by ipa-server-install.
    """
    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    installed = statestore.get_state('installation', 'complete')
    if installed is not None:
        return installed

    # Fall back to the old detection

    installed = (
        fstore.has_files() or (
            not on_master and os.path.exists(paths.IPA_DEFAULT_CONF)
        )
    )

    return installed
