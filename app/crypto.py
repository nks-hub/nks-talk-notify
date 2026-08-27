"""RSA signature verification for the Nextcloud Notifications push-v2 wire format.

Nextcloud signs two different things with the user's identity-proof RSA key
(OC\\Security\\IdentityProof, SHA-512), and the two signatures are NOT
verified the same way:

1. Registration (PushController::registerDevice): the server signs the JSON
   preimage `[cloudId, tokenId]` with openssl_sign(..., OPENSSL_ALGO_SHA512),
   then OVERWRITES `deviceIdentifier` with base64(sha512_raw(preimage)) before
   ever sending it anywhere. The proxy only ever sees that digest, never the
   preimage, so a normal "hash-then-verify" call would hash the digest again
   and never match. It must be verified in "prehashed" mode: the base64-
   decoded deviceIdentifier IS the SHA-512 digest, and the RSA signature is
   verified against that digest directly (PKCS#1 v1.5, DigestInfo built for
   SHA-512, no second hashing).
   Source: apps/notifications/lib/Controller/PushController.php,
   registerDevice(), around the two openssl_sign()/hash() calls.

2. Notification delivery (Push::encryptAndSign / encryptAndSignDelete): the
   server signs the encrypted `subject` ciphertext directly with the same
   OPENSSL_ALGO_SHA512, no pre-hashing trick. This one is verified as a
   normal RSA-SHA512 signature over the base64-decoded subject bytes.
   Source: apps/notifications/lib/Push.php, encryptAndSign() /
   encryptAndSignDelete(), around the openssl_sign($encryptedSubject, ...)
   calls.
"""
from __future__ import annotations

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


class InvalidPublicKey(ValueError):
    pass


def load_rsa_public_key(pem: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise InvalidPublicKey(str(exc)) from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidPublicKey("not an RSA public key")
    return key


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64: {exc}") from exc


def verify_device_identifier_signature(
    *, device_identifier_b64: str, signature_b64: str, public_key_pem: str
) -> bool:
    """Verify a registration/unregistration signature (prehashed SHA-512).

    `device_identifier_b64` is base64(sha512_raw(preimage)); the RSA
    signature was produced over the preimage, so we present the digest we
    already have as a pre-computed SHA-512 hash rather than re-hashing it.
    """
    try:
        digest = _b64decode(device_identifier_b64)
        signature = _b64decode(signature_b64)
    except ValueError:
        return False
    if len(digest) != hashes.SHA512.digest_size:
        return False
    try:
        key = load_rsa_public_key(public_key_pem)
    except InvalidPublicKey:
        return False
    try:
        key.verify(signature, digest, padding.PKCS1v15(), Prehashed(hashes.SHA512()))
    except InvalidSignature:
        return False
    return True


def verify_subject_signature(
    *, subject_b64: str, signature_b64: str, public_key_pem: str
) -> bool:
    """Verify a per-notification signature (plain SHA-512 over the ciphertext)."""
    try:
        message = _b64decode(subject_b64)
        signature = _b64decode(signature_b64)
    except ValueError:
        return False
    try:
        key = load_rsa_public_key(public_key_pem)
    except InvalidPublicKey:
        return False
    try:
        key.verify(signature, message, padding.PKCS1v15(), hashes.SHA512())
    except InvalidSignature:
        return False
    return True
