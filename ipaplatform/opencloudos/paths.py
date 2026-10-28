#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

"""
This OpenCloudOS family base platform module exports default filesystem paths
as common in OpenCloudOS family-based systems.
"""

from __future__ import absolute_import

from ipaplatform.redhat.paths import RedHatPathNamespace


class OpenCloudOSPathNamespace(RedHatPathNamespace):
    NAMED_CRYPTO_POLICY_FILE = "/etc/crypto-policies/back-ends/bind.config"
    SYSCONFIG_NFS = "/etc/nfs.conf"


paths = OpenCloudOSPathNamespace()
