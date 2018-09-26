#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import


import importlib
import sys

from ipaplatform.osinfo import osinfo


class IpaMetaImporter:
    modules = {
        'ipaplatform.constants',
        'ipaplatform.paths',
        'ipaplatform.services',
        'ipaplatform.tasks'
    }

    def __init__(self, platform):
        self.platform = platform

    def find_module(self, fullname, path=None):
        """Meta importer hook"""
        if fullname in self.modules:
            return self
        return None

    def load_module(self, fullname):
        """Meta importer hook"""
        suffix = fullname.split('.', 1)[1]
        alias = 'ipaplatform.{}.{}'.format(self.platform, suffix)
        platform_mod = importlib.import_module(alias)
        base_mod = sys.modules.get(fullname)
        if base_mod is not None:
            # module has been imported before, update its __dict__
            base_mod.__dict__.update(platform_mod.__dict__)
            for key in list(base_mod.__dict__):
                if not hasattr(platform_mod, key):
                    delattr(base_mod, key)
        else:
            sys.modules[fullname] = platform_mod
        return platform_mod


metaimporter = IpaMetaImporter(osinfo.platform)
sys.meta_path.insert(0, metaimporter)

fixup_module = metaimporter.load_module
