#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import os
from ipaplatform.paths import paths

# pylint: disable=unused-import
if paths.ODS_KSMUTIL is not None and os.path.exists(paths.ODS_KSMUTIL):
    from ._ods14 import ODSDBConnection, ODSSignerConn
else:
    from ._ods21 import ODSDBConnection, ODSSignerConn
