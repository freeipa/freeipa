# Copyright (C) 2026 FreeIPA Contributors see COPYING for license
"""IPA configuration paths for the macOS administration client.

Applications can select a private configuration directory with IPA_CONFDIR.
Host installation and external system commands are outside this provider's
scope; inherited server paths do not imply support for server operation.
"""

from ipaplatform.base.paths import BasePathNamespace

paths = BasePathNamespace()
