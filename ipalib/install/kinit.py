#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

# code was moved to ipalib.kinit. This module is now an alias
__all__ = (
    "validate_principal",
    "kinit_keytab",
    "kinit_password",
    "kinit_armor",
    "kinit_pkinit",
)

from ..kinit import (
    validate_principal,
    kinit_keytab,
    kinit_password,
    kinit_armor,
    kinit_pkinit,
)
