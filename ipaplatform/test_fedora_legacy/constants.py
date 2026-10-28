#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#
"""Fedora AES HMAC-SHA1 master key constants
"""
from ipaplatform.fedora.constants import FedoraConstantsNamespace, User, Group


__all__ = ("constants", "User", "Group")


class TestFedoraLegacyConstantsNamespace(FedoraConstantsNamespace):
    pass


constants = TestFedoraLegacyConstantsNamespace()
