#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""RHEL container tasks
"""
from ipaplatform.rhel.tasks import RHELTaskNamespace


class RHELContainerTaskNamespace(RHELTaskNamespace):
    pass


tasks = RHELContainerTaskNamespace()
