#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

'''
This nixos base platform module exports platform related constants.
'''

# Fallback to default constant definitions
from __future__ import absolute_import

from ipaplatform.redhat.constants import (
    RedHatConstantsNamespace, User, Group
)

HAS_NFS_CONF = True


__all__ = ("constants", "User", "Group")


class NixosConstantsNamespace(RedHatConstantsNamespace):
    MOD_WSGI_PYTHON2 = "modules/mod_wsgi.so"
    MOD_WSGI_PYTHON3 = "modules/mod_wsgi_python3.so"

    if HAS_NFS_CONF:
        SECURE_NFS_VAR = None

    NAMED_OPENSSL_ENGINE = "pkcs11"


constants = NixosConstantsNamespace()
