#
# Copyright (C) 2020 FreeIPA Contributors, see COPYING for license
#

"""
This SUSE OS family base platform module exports default platform
related constants for the SUSE OS family-based systems.
"""

# Fallback to default path definitions
from ipaplatform.base.constants import BaseConstantsNamespace


class SuseConstantsNamespace(BaseConstantsNamespace):
    HTTPD_USER = "wwwrun"
    HTTPD_GROUP = "www"
    # Don't have it yet
    SSSD_USER = "root"
    TLS_HIGH_CIPHERS = None


constants = SuseConstantsNamespace()
