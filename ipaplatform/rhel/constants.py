#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This RHEL base platform module exports platform related constants.
'''

# Fallback to default constant definitions
from __future__ import absolute_import

from ipaplatform.redhat.constants import RedHatConstantsNamespace
from ipaplatform.osinfo import osinfo

# RHEL 7 and earlier use /etc/sysconfig/nfs
# RHEL 8 uses /etc/nfs.conf
HAS_NFS_CONF = osinfo.version_number >= (8,)


class RHELConstantsNamespace(RedHatConstantsNamespace):
    IPA_ADTRUST_PACKAGE_NAME = "ipa-server-trust-ad"
    IPA_DNS_PACKAGE_NAME = "ipa-server-dns"
    if HAS_NFS_CONF:
        SECURE_NFS_VAR = None

constants = RHELConstantsNamespace()
