# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""
JSON Web Key (JWK) implementation without jose dependency

Extracted from acme.py to avoid circular imports between
acme and storage_acme.
"""

import base64
import hashlib
import json
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa, ec


class JWK:
    """JSON Web Key implementation without jose dependency"""

    @staticmethod
    def from_cryptography_key(key) -> Dict[str, Any]:
        """Convert cryptography key to JWK format"""
        if isinstance(key, rsa.RSAPublicKey):
            numbers = key.public_numbers()
            return {
                "kty": "RSA",
                "n": JWK._encode_bigint(numbers.n),
                "e": JWK._encode_bigint(numbers.e),
            }
        elif isinstance(key, rsa.RSAPrivateKey):
            return JWK.from_cryptography_key(key.public_key())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            if key.curve.name == "secp256r1":
                curve = "P-256"
            elif key.curve.name == "secp384r1":
                curve = "P-384"
            elif key.curve.name == "secp521r1":
                curve = "P-521"
            else:
                raise ValueError(f"Unsupported curve: {key.curve.name}")

            numbers = key.public_numbers()
            return {
                "kty": "EC",
                "crv": curve,
                "x": JWK._encode_ec_coordinate(numbers.x, key.curve),
                "y": JWK._encode_ec_coordinate(numbers.y, key.curve),
            }
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            return JWK.from_cryptography_key(key.public_key())
        else:
            raise ValueError(f"Unsupported key type: {type(key)}")

    @staticmethod
    def _encode_bigint(value: int) -> str:
        """Encode big integer to base64url"""
        byte_length = max(1, (value.bit_length() + 7) // 8)
        return (
            base64.urlsafe_b64encode(
                value.to_bytes(byte_length, byteorder="big")
            )
            .decode()
            .rstrip("=")
        )

    @staticmethod
    def _encode_ec_coordinate(value: int, curve) -> str:
        """Encode EC coordinate to base64url"""
        if curve.name == "secp256r1":
            byte_length = 32
        elif curve.name == "secp384r1":
            byte_length = 48
        elif curve.name == "secp521r1":
            byte_length = 66
        else:
            raise ValueError(f"Unsupported curve: {curve.name}")

        return (
            base64.urlsafe_b64encode(
                value.to_bytes(byte_length, byteorder="big")
            )
            .decode()
            .rstrip("=")
        )

    @staticmethod
    def thumbprint(jwk_dict: Dict[str, Any]) -> str:
        """Calculate JWK thumbprint (RFC 7638)"""
        if "kty" not in jwk_dict:
            raise ValueError("Missing required JWK field: kty")
        kty = jwk_dict["kty"]
        if kty == "RSA":
            for field in ("e", "n"):
                if field not in jwk_dict:
                    raise ValueError(
                        f"Missing required RSA JWK field: {field}"
                    )
            canonical = {
                "e": jwk_dict["e"],
                "kty": kty,
                "n": jwk_dict["n"],
            }
        elif kty == "EC":
            for field in ("crv", "x", "y"):
                if field not in jwk_dict:
                    raise ValueError(f"Missing required EC JWK field: {field}")
            canonical = {
                "crv": jwk_dict["crv"],
                "kty": kty,
                "x": jwk_dict["x"],
                "y": jwk_dict["y"],
            }
        else:
            raise ValueError(f"Unsupported key type: {kty}")

        json_bytes = json.dumps(canonical, separators=(",", ":")).encode(
            "utf-8"
        )
        digest = hashlib.sha256(json_bytes).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")
