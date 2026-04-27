# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Composite CA storage backend combining all storage modules.
Provides backward compatibility with existing CAStorageBackend usage.
"""

from __future__ import absolute_import

from ipathinca.storage_base import BaseStorageBackend
from ipathinca.storage_certificates import CertificateStorage
from ipathinca.storage_profiles import ProfileStorage
from ipathinca.storage_crl import CRLStorage
from ipathinca.storage_maintenance import MaintenanceStorage
from ipathinca.storage_subca import SubCAStorage
from ipathinca.storage_ranges import RangeStorage
from ipathinca.storage_hsm import HSMStorage


class CAStorageBackend(
    CertificateStorage,
    ProfileStorage,
    CRLStorage,
    MaintenanceStorage,
    SubCAStorage,
    RangeStorage,
    HSMStorage,
    BaseStorageBackend,
):
    """
    Complete CA storage backend combining all storage modules.

    This class uses multiple inheritance to provide a unified interface
    to all CA storage operations. Maintains backward compatibility.

    New code should use specific storage classes for better modularity:
    - CertificateStorage for cert/request operations
    - CRLStorage for CRL operations
    - SubCAStorage for sub-CA management
    - ProfileStorage for profile operations
    - RangeStorage for replica range management
    - HSMStorage for HSM configuration
    - MaintenanceStorage for cleanup/pruning
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
