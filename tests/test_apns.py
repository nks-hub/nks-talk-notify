from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from app import apns
from app.provider_errors import ProviderResponseError


@pytest.fixture
def ec_key_path(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path = tmp_path / "AuthKey_TEST.p8"
    path.write_bytes(pem)
    return path, key


def _b64url_decode(s: str) -> bytes:
    padding_needed = -len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding_needed)


def test_jwt_has_expected_header_and_claims(ec_key_path):
    path, key = ec_key_path
    factory = apns.ApnsAuthTokenFactory(str(path), key_id="KEYID1234", team_id="TEAMID5678")
    token = factory.token()

    header_b64, payload_b64, signature_b64 = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))

    assert header == {"alg": "ES256", "kid": "KEYID1234"}
    assert payload["iss"] == "TEAMID5678"
    assert isinstance(payload["iat"], int)


def test_jwt_signature_verifies_against_public_key(ec_key_path):
    path, key = ec_key_path
    factory = apns.ApnsAuthTokenFactory(str(path), key_id="k", team_id="t")
    token = factory.token()
    signing_input, signature_b64 = token.rsplit(".", 1)

    raw_signature = _b64url_decode(signature_b64)
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:], "big")
    der_signature = encode_dss_signature(r, s)

    key.public_key().verify(der_signature, signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))


def test_token_is_cached_within_lifetime(ec_key_path):
    path, _key = ec_key_path
    factory = apns.ApnsAuthTokenFactory(str(path), key_id="k", team_id="t")
    assert factory.token() == factory.token()


def test_rejects_rsa_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path = tmp_path / "wrong-key-type.p8"
    path.write_bytes(pem)
    with pytest.raises(ValueError):
        apns.ApnsAuthTokenFactory(str(path), key_id="k", team_id="t")


@pytest.mark.parametrize(
    "nc_type,nc_priority,expected_push_type,expected_priority",
    [
        ("voip", "high", "voip", 10),
        ("alert", "high", "alert", 10),
        ("alert", "normal", "alert", 5),
        ("background", "normal", "background", 5),
    ],
)
def test_push_type_and_priority_mapping(nc_type, nc_priority, expected_push_type, expected_priority):
    push_type, priority = apns.push_type_and_priority(nc_type, nc_priority)
    assert (push_type, priority) == (expected_push_type, expected_priority)


def test_alert_payload_is_generic_and_mutable():
    payload = apns.build_payload(push_type="alert", encrypted_subject_b64="Y2lwaGVy")
    assert payload["aps"]["mutable-content"] == 1
    assert "title" in payload["aps"]["alert"]
    assert payload["nc-subject"] == "Y2lwaGVy"


def test_voip_payload_has_no_displayable_alert():
    payload = apns.build_payload(push_type="voip", encrypted_subject_b64="Y2lwaGVy")
    assert "alert" not in payload["aps"]
    assert payload["nc-subject"] == "Y2lwaGVy"


def test_background_payload_is_silent():
    payload = apns.build_payload(push_type="background", encrypted_subject_b64="Y2lwaGVy")
    assert payload["aps"] == {"content-available": 1}


def test_apns_result_should_forget_device_on_410():
    result = apns.ApnsResult(status_code=410, apns_id="x", reason="Unregistered")
    assert result.should_forget_device


def test_apns_result_should_forget_device_on_bad_device_token():
    result = apns.ApnsResult(status_code=400, apns_id=None, reason="BadDeviceToken")
    assert result.should_forget_device


def test_apns_result_keeps_device_on_other_errors():
    result = apns.ApnsResult(status_code=400, apns_id=None, reason="BadTopic")
    assert not result.should_forget_device
    result2 = apns.ApnsResult(status_code=429, apns_id=None, reason="TooManyRequests")
    assert not result2.should_forget_device


def test_client_selects_endpoint_per_registered_environment(ec_key_path):
    path, _key = ec_key_path
    client = apns.ApnsClient(
        str(path),
        key_id="k",
        team_id="t",
        topic="com.example.app",
        use_sandbox=True,
    )

    class FakeResponse:
        status_code = 200
        headers: dict[str, str] = {}

    class FakeHttpClient:
        def __init__(self):
            self.calls = []

        def post(self, path, **kwargs):
            self.calls.append((path, kwargs))
            return FakeResponse()

        def close(self):
            pass

    for original in client._clients.values():
        original.close()
    development = FakeHttpClient()
    production = FakeHttpClient()
    client._clients = {
        apns.DEVELOPMENT_ENVIRONMENT: development,
        apns.PRODUCTION_ENVIRONMENT: production,
    }
    try:
        client.send(
            device_token="aa" * 32,
            payload={"aps": {}},
            push_type="background",
            priority=5,
            environment=apns.PRODUCTION_ENVIRONMENT,
        )
    finally:
        client.close()

    assert development.calls == []
    assert len(production.calls) == 1


def test_client_rejects_non_object_error_response(ec_key_path):
    path, _key = ec_key_path
    client = apns.ApnsClient(
        str(path),
        key_id="k",
        team_id="t",
        topic="com.example.app",
    )

    class FakeResponse:
        status_code = 500
        headers: dict[str, str] = {}

        @staticmethod
        def json():
            return []

    class FakeHttpClient:
        def post(self, path, **kwargs):
            return FakeResponse()

        def close(self):
            pass

    for original in client._clients.values():
        original.close()
    client._clients = {
        apns.DEVELOPMENT_ENVIRONMENT: FakeHttpClient(),
        apns.PRODUCTION_ENVIRONMENT: FakeHttpClient(),
    }
    try:
        with pytest.raises(ProviderResponseError):
            client.send(
                device_token="aa" * 32,
                payload={"aps": {}},
                push_type="background",
                priority=5,
            )
    finally:
        client.close()
