#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from .install import Server

from .replicainstall import install_check as replica_install_check
from .replicainstall import install as replica_install
from .upgrade import upgrade_check, upgrade
