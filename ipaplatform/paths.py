#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
"""IpaMetaImporter replaces this module with ipaplatform.$NAME.paths.
"""
import ipaplatform._importhook

ipaplatform._importhook.fixup_module('ipaplatform.paths')
