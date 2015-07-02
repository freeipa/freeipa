#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This RHEL base platform module exports platform related constants.
'''

# Fallback to default constant definitions
from ipaplatform.redhat.constants import RedHatConstantsNamespace


class RHELConstantsNamespace(RedHatConstantsNamespace):
    pass

constants = RHELConstantsNamespace()
