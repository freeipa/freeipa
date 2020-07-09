#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Fedora container tasks
"""
from ipaplatform.fedora.tasks import FedoraTaskNamespace


class FedoraContainerTaskNamespace(FedoraTaskNamespace):
    pass


tasks = FedoraContainerTaskNamespace()
