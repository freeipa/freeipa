#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""FreeIPA API package
"""
from __future__ import absolute_import

from ._internal.api import get_api
from ._internal.common import mangle_exports as _mangle_exports

from . import errors

from ipapython.dn import DN
from ipapython.kerberos import Principal


__all__ = (
    "get_api",
    # additional tools from ipapython
    "DN",
    "Principal",
)

# make exported names to appear to originate from ipaapi
_mangle_exports(__name__)
_mangle_exports(errors.__name__)
