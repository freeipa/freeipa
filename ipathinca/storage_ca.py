# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
CA storage backend combining all CA storage modules.
Provides unified interface for CA operations.
"""

from __future__ import absolute_import

from ipathinca.storage_base import BaseStorageBackend
from ipathinca.storage_certificates import CertificateStorage
from ipathinca.storage_profiles import ProfileStorage
from ipathinca.storage_crl import CRLStorage
from ipathinca.storage_maintenance import MaintenanceStorage
from ipathinca.storage_subca import SubCAStorage
from ipathinca.storage_ranges import RangeStorage


class CAStorageBackend(
    CertificateStorage,
    ProfileStorage,
    CRLStorage,
    MaintenanceStorage,
    SubCAStorage,
    RangeStorage,
    BaseStorageBackend,
):
    """
    CA storage backend combining all CA storage modules.

    This class uses multiple inheritance to provide a unified interface
    to CA storage operations.

    Provides:
    - CertificateStorage for cert/request operations
    - ProfileStorage for profile operations
    - CRLStorage for CRL operations
    - MaintenanceStorage for cleanup/pruning
    - SubCAStorage for sub-CA management
    - RangeStorage for replica range management
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
