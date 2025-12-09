# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
CA storage backend combining certificate and profile storage.
Provides unified interface for CA operations.
"""

from __future__ import absolute_import

from ipathinca.storage_base import BaseStorageBackend
from ipathinca.storage_certificates import CertificateStorage
from ipathinca.storage_profiles import ProfileStorage


class CAStorageBackend(CertificateStorage, ProfileStorage, BaseStorageBackend):
    """
    CA storage backend for certificate and profile operations.

    This class uses multiple inheritance to provide a unified interface
    to CA storage operations.

    Provides:
    - CertificateStorage for cert/request operations
    - ProfileStorage for profile operations
    """

    def __init__(
        self,
        ca_id="ipa",
        random_serial_numbers=False,
        serial_number_bits=128,
        collision_recovery_attempts=100,
    ):
        """Initialize CA storage backend."""
        BaseStorageBackend.__init__(
            self,
            ca_id,
            random_serial_numbers,
            serial_number_bits,
            collision_recovery_attempts,
        )
