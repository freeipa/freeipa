#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

"""Meta import hook for ipaplatform.

Known Linux distros with /etc/os-release
----------------------------------------

- alpine
- centos (like rhel, fedora)
- debian
- fedora
- rhel
- ubuntu (like debian)
"""

import importlib
import io
import re
import sys
import warnings


import ipaplatform
try:
    from ipaplatform.override import OVERRIDE
except ImportError:
    OVERRIDE = None


_osrelease_line = re.compile(
    u"^(?!#)(?P<name>[a-zA-Z0-9_]+)="
    u"(?P<quote>[\"\']?)(?P<value>.+)(?P=quote)$"
)


class IpaMetaImporter(object):
    """Meta import hook and platform detector.

    The meta import hook uses /etc/os-release to auto-detects the best
    matching ipaplatform provider. It is compatible with external namespace
    packages, too.
    """
    modules = {
        'ipaplatform.constants',
        'ipaplatform.paths',
        'ipaplatform.services',
        'ipaplatform.tasks'
    }

    bsd_family = (
        'freebsd',
        'openbsd',
        'netbsd',
        'dragonfly',
        'gnukfreebsd'
    )

    def __init__(self, override=OVERRIDE):
        self.override = override
        self.platform_ids = self._get_platform_ids(self.override)
        self.platform = self._get_platform(self.platform_ids)

    def _get_platform_ids(self, override):
        platforms = []
        # allow RPM and Debian packages to override platform
        if override is not None:
            platforms.append(override)

        if sys.platform.startswith('linux'):
            # Linux, get distribution from /etc/os-release
            try:
                platforms.extend(self._parse_osrelease())
            except Exception as e:
                warnings.warn("Failed to read /etc/os-release: {}".format(e))
        elif sys.platform == 'win32':
            # Windows 32 or 64bit platform
            platforms.append('win32')
        elif sys.platform == 'darwin':
            # macOS
            platforms.append('macos')
        elif sys.platform.startswith(self.bsd_family):
            # BSD family, look for e.g. ['freebsd10', 'freebsd']
            platforms.append(sys.platform)
            simple = sys.platform.rstrip('0123456789')
            if simple != sys.platform:
                platforms.append(simple)

        if not platforms:
            raise ValueError("Unsupported platform: {}".format(sys.platform))

        return platforms

    def _parse_osrelease(self, filename='/etc/os-release'):
        release = {}
        with io.open(filename, encoding='utf-8') as f:
            for line in f:
                mo = _osrelease_line.match(line)
                if mo is not None:
                    release[mo.group('name')] = mo.group('value')

        platforms = [
            release['ID'],
        ]
        if "ID_LIKE" in release:
            platforms.extend(
                v.strip() for v in release['ID_LIKE'].split(' ') if v.strip()
            )

        return platforms

    def _get_platform(self, platform_ids):
        for platform in platform_ids:
            try:
                importlib.import_module('ipaplatform.{}'.format(platform))
            except ImportError:
                pass
            else:
                return platform
        raise ImportError('No ipaplatform available for "{}"'.format(
                          ', '.join(platform_ids)))

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


metaimporter = IpaMetaImporter()
sys.meta_path.insert(0, metaimporter)

fixup_module = metaimporter.load_module
ipaplatform.NAME = metaimporter.platform
