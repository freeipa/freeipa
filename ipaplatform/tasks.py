#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
"""IpaMetaImporter replaces this module with ipaplatform.$NAME.tasks.
"""
# flake8: noqa
# pylint: disable=unused-import

from .base.tasks import tasks
from . import _importhook
