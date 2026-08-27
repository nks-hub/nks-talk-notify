from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass
class FakeDevice:
    """A synthetic device registration, signed the way Nextcloud signs one.

    Mirrors PushController::registerDevice(): sign the JSON preimage with
    SHA-512 PKCS#1 v1.5, then publish only base64(sha512(preimage)) as the
    deviceIdentifier -- never the preimage itself.
    """

    private_key: rsa.RSAPrivateKey
    public_key_pem: str
    device_identifier: str
    signature: str

    def sign_subject(self, subject_bytes: bytes) -> str:
        sig = self.private_key.sign(subject_bytes, padding.PKCS1v15(), hashes.SHA512())
        return base64.b64encode(sig).decode()


def make_fake_device(preimage: bytes = b'["alice@cloud.example","42"]') -> FakeDevice:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    signature = key.sign(preimage, padding.PKCS1v15(), hashes.SHA512())
    digest = hashlib.sha512(preimage).digest()

    return FakeDevice(
        private_key=key,
        public_key_pem=public_pem,
        device_identifier=base64.b64encode(digest).decode(),
        signature=base64.b64encode(signature).decode(),
    )


@pytest.fixture
def fake_device() -> FakeDevice:
    return make_fake_device()
