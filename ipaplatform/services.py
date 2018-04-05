#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
"""IpaMetaImporter replaces this module with ipaplatform.$NAME.services.
"""
from __future__ import absolute_import

import ipaplatform._importhook

ipaplatform._importhook.fixup_module('ipaplatform.services')
