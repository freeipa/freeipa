#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This Fedora base platform module exports platform related constants.
'''

# Fallback to default constant definitions
from ipaplatform.redhat.constants import RedHatConstantsNamespace


class FedoraConstantsNamespace(RedHatConstantsNamespace):
    pass

constants = FedoraConstantsNamespace()
