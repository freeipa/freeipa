#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import sys

# The Darwin provider supports remote administration only. Reject the whole
# host installer before it can load dependencies or modify local credentials.
if sys.platform == 'darwin':
    raise ImportError('Host installation is unsupported on macOS')
