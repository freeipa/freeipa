#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from .install import install_check, install, uninstall_check, uninstall
from .replicainstall import install_check as replica_install_check
from .replicainstall import install as replica_install

from .install import validate_dm_password, validate_admin_password
from .upgrade import upgrade_configuration
