# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Key generation utilities for ipacta.

Centralises private-key generation so that certs.py, nss_utils.py, and
kra.py can all dispatch on algorithm type without circular imports.
"""

from __future__ import absolute_import

import logging

from cryptography.hazmat.primitives.asymmetric import rsa, ec

logger = logging.getLogger(__name__)

DEFAULT_RSA_KEY_SIZE = 3072

_NSS_CURVE_MAP = {
    "nistp256": ec.SECP256R1(),
    "nistp384": ec.SECP384R1(),
    "nistp521": ec.SECP521R1(),
}

_SYNTA_CURVE_MAP = {
    "p-256": ec.SECP256R1(),
    "p-384": ec.SECP384R1(),
    "p-521": ec.SECP521R1(),
}

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.hazmat.primitives.asymmetric.mldsa import generate_key  # pylint: disable=unused-import  # noqa: F401
    MLDSA_AVAILABLE = True
except ImportError:
    MLDSA_AVAILABLE = False


def generate_private_key(
    signing_alg, key_size, ec_curve="P-256"
):
    """Generate a private key appropriate for the given signing algorithm.

    Args:
        signing_alg: PKI algorithm string such as ``"SHA256withRSA"``,
                     ``"SHA256withEC"``, or ``"ML-DSA-65"``.
        key_size:    RSA key size in bits (ignored for EC and ML-DSA).
        ec_curve:    EC curve name in either NSS/Dogtag form ("nistp256")
                     or standard form ("P-256").
                     Ignored for RSA and ML-DSA.

    Returns:
        A freshly generated private key.

    Raises:
        ValueError: For unknown ML-DSA parameter sets or unavailable
                    ML-DSA support.
    """
    alg_upper = signing_alg.upper()

    if "ML-DSA" in alg_upper or "MLDSA" in alg_upper:
        if not MLDSA_AVAILABLE:
            raise ValueError(
                "ML-DSA key generation requires "
                "python-cryptography >= 49.0 with OpenSSL >= 3.5"
            )
        for param_set, gen_fn in (
            ("ML-DSA-87", mldsa.MLDSA87PrivateKey.generate),
            ("ML-DSA-65", mldsa.MLDSA65PrivateKey.generate),
            ("ML-DSA-44", mldsa.MLDSA44PrivateKey.generate),
        ):
            if param_set in alg_upper:
                logger.debug("Generating %s private key", param_set)
                return gen_fn()
        raise ValueError(
            f"Unknown ML-DSA parameter set in signing algorithm:"
            f" {signing_alg!r}"
        )

    if "EC" in alg_upper or "ECDSA" in alg_upper:
        curve = (
            _NSS_CURVE_MAP.get(ec_curve.lower())
            or _SYNTA_CURVE_MAP.get(ec_curve.lower())
        )
        if curve is None:
            curve = ec.SECP256R1()
            logger.warning(
                "Unknown EC curve %s, falling back to P-256", ec_curve
            )
        logger.debug("Generating EC private key (%s)", ec_curve)
        return ec.generate_private_key(curve)

    logger.debug("Generating %d-bit RSA private key", key_size)
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
