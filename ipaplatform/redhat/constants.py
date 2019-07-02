#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This Red Hat OS family base platform module exports default platform
related constants for the Red Hat OS family-based systems.
'''

# Fallback to default path definitions
from __future__ import absolute_import

from ipaplatform.base.constants import BaseConstantsNamespace


class RedHatConstantsNamespace(BaseConstantsNamespace):
    # System-wide crypto policy, but without TripleDES, pre-shared key,
    # secure remote password, and DSA cert authentication.
    # see https://fedoraproject.org/wiki/Changes/CryptoPolicy
    TLS_HIGH_CIPHERS = "PROFILE=SYSTEM:!3DES:!PSK:!SRP:!aDSS"


constants = RedHatConstantsNamespace()
