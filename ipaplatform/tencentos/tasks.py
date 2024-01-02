#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

"""
This module contains default TencentOS-specific implementations of system tasks.
"""

from __future__ import absolute_import

from ipaplatform.redhat.tasks import RedHatTaskNamespace


class TencentOSTaskNamespace(RedHatTaskNamespace):
    pass


tasks = TencentOSTaskNamespace()
