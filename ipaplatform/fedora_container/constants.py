#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Fedora container constants
"""
from ipaplatform.fedora.constants import FedoraConstantsNamespace, User, Group


__all__ = ("constants", "User", "Group")


class FedoraContainerConstantsNamespace(FedoraConstantsNamespace):
    pass


constants = FedoraContainerConstantsNamespace()
