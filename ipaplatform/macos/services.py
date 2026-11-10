# Copyright (C) 2026 FreeIPA Contributors see COPYING for license
"""Service management is unavailable on the macOS administration client."""

from ipaplatform.base.services import KnownServices


def service(name, api=None):
    raise NotImplementedError('Service management is unsupported on macOS')


knownservices = KnownServices({})
timedate_services = []
