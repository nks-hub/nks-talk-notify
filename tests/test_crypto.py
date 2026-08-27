from __future__ import annotations

import base64

from app import crypto
from .conftest import make_fake_device


def test_valid_device_identifier_signature_verifies():
    device = make_fake_device()
    assert crypto.verify_device_identifier_signature(
        device_identifier_b64=device.device_identifier,
        signature_b64=device.signature,
        public_key_pem=device.public_key_pem,
    )


def test_device_identifier_signature_rejects_wrong_key():
    device = make_fake_device()
    other = make_fake_device()
    assert not crypto.verify_device_identifier_signature(
        device_identifier_b64=device.device_identifier,
        signature_b64=device.signature,
        public_key_pem=other.public_key_pem,
    )


def test_load_rsa_public_key_rejects_undersized_key():
    """A key that parses fine as RSA but is too weak to be a real identity
    key (and, with no floor at all, too cheap to spam registrations with)."""
    import cryptography.hazmat.primitives.asymmetric.rsa as rsa_mod
    import cryptography.hazmat.primitives.serialization as ser

    weak_key = rsa_mod.generate_private_key(public_exponent=65537, key_size=1024)
    weak_pem = weak_key.public_key().public_bytes(
        ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    try:
        crypto.load_rsa_public_key(weak_pem)
        assert False, "expected InvalidPublicKey for a 1024-bit key"
    except crypto.InvalidPublicKey:
        pass

    # and the higher-level verify functions must degrade to False, not raise
    assert not crypto.verify_device_identifier_signature(
        device_identifier_b64=base64.b64encode(b"x" * 64).decode(), signature_b64=base64.b64encode(b"y").decode(),
        public_key_pem=weak_pem,
    )


def test_device_identifier_signature_rejects_tampered_digest():
    device = make_fake_device()
    tampered = base64.b64encode(b"x" * 64).decode()
    assert not crypto.verify_device_identifier_signature(
        device_identifier_b64=tampered,
        signature_b64=device.signature,
        public_key_pem=device.public_key_pem,
    )


def test_plain_hash_verify_would_have_rejected_the_valid_pair():
    """Documents WHY prehashed verification is required.

    A naive "hash message then verify" call re-hashes the digest we already
    have, which never matches the original preimage-based signature. This
    pins the exact bug a careless reimplementation would hit.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes as h
    from cryptography.hazmat.primitives.asymmetric import padding

    device = make_fake_device()
    key = crypto.load_rsa_public_key(device.public_key_pem)
    digest = base64.b64decode(device.device_identifier)
    signature = base64.b64decode(device.signature)
    try:
        key.verify(signature, digest, padding.PKCS1v15(), h.SHA512())
        raised = False
    except InvalidSignature:
        raised = True
    assert raised, "plain (non-prehashed) verification should NOT accept this signature"


def test_valid_subject_signature_verifies():
    device = make_fake_device()
    subject = b"\x01\x02\x03ciphertext-stand-in"
    signature = device.sign_subject(subject)
    assert crypto.verify_subject_signature(
        subject_b64=base64.b64encode(subject).decode(),
        signature_b64=signature,
        public_key_pem=device.public_key_pem,
    )


def test_subject_signature_rejects_tampered_subject():
    device = make_fake_device()
    subject = b"original-subject-bytes"
    signature = device.sign_subject(subject)
    assert not crypto.verify_subject_signature(
        subject_b64=base64.b64encode(b"different-bytes").decode(),
        signature_b64=signature,
        public_key_pem=device.public_key_pem,
    )


def test_invalid_base64_is_rejected_not_raised():
    assert not crypto.verify_device_identifier_signature(
        device_identifier_b64="not-valid-base64!!!",
        signature_b64="also-not-base64!!!",
        public_key_pem="not a pem",
    )
