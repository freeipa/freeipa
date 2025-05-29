#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#
"""Fedora AES HMAC-SHA1 master key paths
"""
from ipaplatform.fedora.paths import FedoraPathNamespace


class FedoraAesSha1PathNamespace(FedoraPathNamespace):
    pass


paths = FedoraAesSha1PathNamespace()
