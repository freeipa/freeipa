#
# Copyright (C) 2020 FreeIPA Contributors, see COPYING for license
#

"""
This SUSE OS family base platform module exports default platform
related constants for the SUSE OS family-based systems.
"""

# Fallback to default path definitions
from ipaplatform.base.constants import BaseConstantsNamespace, User, Group


class SuseConstantsNamespace(BaseConstantsNamespace):
    HTTPD_USER = User("wwwrun")
    HTTPD_GROUP = Group("www")
    # Don't have it yet
    SSSD_USER = User("root")
    TLS_HIGH_CIPHERS = None


constants = SuseConstantsNamespace()
