#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""RHEL container constants
"""
from ipaplatform.rhel.constants import RHELConstantsNamespace, User, Group


__all__ = ("constants", "User", "Group")


class RHELContainerConstantsNamespace(RHELConstantsNamespace):
    pass


constants = RHELContainerConstantsNamespace()
