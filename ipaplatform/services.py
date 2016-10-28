#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
"""IpaMetaImporter replaces this module with ipaplatform.$NAME.services.
"""
# flake8: noqa
# pylint: disable=unused-import

from .base.services import wellknownservices, wellknownports
from .base.services import service, knownservices, timedate_services
from . import _importhook
