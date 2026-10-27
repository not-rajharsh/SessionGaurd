"""proof: layer 2 crypto helpers for the device-bound key.

The browser holds a NON-EXTRACTABLE ECDSA P-256 private key (WebCrypto) and
sends only the SPKI public key. A proof is a signature over the UTF-8 string
"<nonce>|<purpose>" where purpose is "presence" or "<METHOD> <path>", so a
signature for one action cannot be replayed for another. WebCrypto emits raw
r||s (IEEE P1363, 64 bytes); we convert to DER for `cryptography`.
"""
from __future__ import annotations

import base64
import binascii
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def _b64decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")  # accept std and url-safe
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def parse_public_key(spki_b64: str) -> ec.EllipticCurvePublicKey:
    """Return the key or raise ValueError. Only P-256 EC keys are accepted."""
    try:
        key = serialization.load_der_public_key(_b64decode(spki_b64))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("not a valid SPKI public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("public key must be ECDSA P-256")
    return key


def verify_signature(spki_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        key = parse_public_key(spki_b64)
        raw = _b64decode(signature_b64)
        if len(raw) != 64:
            return False
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, binascii.Error, InvalidSignature):
        return False


def new_nonce() -> str:
    return secrets.token_urlsafe(32)


def signed_message(nonce: str, purpose: str) -> bytes:
    return f"{nonce}|{purpose}".encode()
