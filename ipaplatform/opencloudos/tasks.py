#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

"""
This module contains default OpenCloudOS family-specific implementations of
system tasks.
"""

from __future__ import absolute_import

from ipaplatform.redhat.tasks import RedHatTaskNamespace


class OpenCloudOSTaskNamespace(RedHatTaskNamespace):
    pass


tasks = OpenCloudOSTaskNamespace()
