# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
Composite CA storage backend combining all storage modules.
Provides backward compatibility with existing CAStorageBackend usage.
"""

from __future__ import absolute_import

from ipacta.storage.base import BaseStorageBackend
from ipacta.storage.certificates import CertificateStorage
from ipacta.storage.profiles import ProfileStorage
from ipacta.storage.crl import CRLStorage
from ipacta.storage.maintenance import MaintenanceStorage
from ipacta.storage.subca import SubCAStorage
from ipacta.storage.ranges import RangeStorage
from ipacta.storage.hsm import HSMStorage


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
