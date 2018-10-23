#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This RHEL base platform module exports platform related constants.
'''

# Fallback to default constant definitions
from __future__ import absolute_import

from ipaplatform.redhat.constants import RedHatConstantsNamespace


class RHELConstantsNamespace(RedHatConstantsNamespace):
    IPA_ADTRUST_PACKAGE_NAME = "ipa-server-trust-ad"
    IPA_DNS_PACKAGE_NAME = "ipa-server-dns"

constants = RHELConstantsNamespace()
