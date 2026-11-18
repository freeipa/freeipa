# Copyright (C) 2026 FreeIPA Contributors see COPYING for license
"""IPA configuration paths for the macOS administration client.

Applications can select a private configuration directory with IPA_CONFDIR.
Host installation and external system commands are outside this provider's
scope; inherited server paths do not imply support for server operation.
"""

import os

from ipaplatform.base.paths import BasePathNamespace


class MacOSPathNamespace(BasePathNamespace):
    def __init__(self):
        confdir = os.environ.get('IPA_CONFDIR')
        if confdir is not None:
            if not os.path.isabs(confdir) or not os.path.isdir(confdir):
                raise ValueError(
                    'IPA_CONFDIR must be an absolute path to an existing '
                    'directory')
            self.IPA_CA_CRT = os.path.join(confdir, 'ca.crt')
            self.IPA_DEFAULT_CONF = os.path.join(confdir, 'default.conf')


paths = MacOSPathNamespace()
