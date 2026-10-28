#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Facts about the installation
"""

import logging
import os
from . import sysrestore
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

# Used to determine install status
IPA_MODULES = [
    'httpd', 'kadmin', 'dirsrv', 'pki-tomcatd', 'install', 'krb5kdc', 'named']


def is_ipa_configured():
    """
    Use the state to determine if IPA has been configured.
    """
    sstore = sysrestore.StateFile(paths.SYSRESTORE)
    if sstore.has_state('installation'):
        return sstore.get_state('installation', 'complete')

    # Fall back to older method in case this is an existing installation

    installed = False

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    for module in IPA_MODULES:
        if sstore.has_state(module):
            logger.debug('%s is configured', module)
            installed = True
        else:
            logger.debug('%s is not configured', module)

    if fstore.has_files():
        logger.debug('filestore has files')
        installed = True
    else:
        logger.debug('filestore is tracking no files')

    return installed


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
