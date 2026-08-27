from __future__ import annotations

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import fcm


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.fixture
def service_account_path(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    account = {
        "type": "service_account",
        "project_id": "nks-talk-notify-test",
        "private_key": private_pem,
        "client_email": "fcm-sender@nks-talk-notify-test.iam.gserviceaccount.com",
    }
    path = tmp_path / "service-account.json"
    path.write_text(json.dumps(account))
    return path, key


def test_assertion_has_expected_claims(service_account_path):
    path, _key = service_account_path
    factory = fcm.FcmAuthTokenFactory(str(path))
    assertion = factory.build_assertion(1_800_000_000.0)

    header_b64, claims_b64, _sig = assertion.split(".")
    header = json.loads(_b64url_decode(header_b64))
    claims = json.loads(_b64url_decode(claims_b64))

    assert header == {"alg": "RS256", "typ": "JWT"}
    assert claims["iss"] == "fcm-sender@nks-talk-notify-test.iam.gserviceaccount.com"
    assert claims["scope"] == "https://www.googleapis.com/auth/firebase.messaging"
    assert claims["aud"] == "https://oauth2.googleapis.com/token"
    assert claims["exp"] == claims["iat"] + 3600


def test_assertion_signature_verifies_against_public_key(service_account_path):
    path, key = service_account_path
    factory = fcm.FcmAuthTokenFactory(str(path))
    assertion = factory.build_assertion(1_800_000_000.0)
    signing_input, signature_b64 = assertion.rsplit(".", 1)

    key.public_key().verify(
        _b64url_decode(signature_b64), signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )  # raises if invalid


def test_rejects_non_service_account_json(tmp_path):
    bad = tmp_path / "not-a-service-account.json"
    bad.write_text(json.dumps({"client_email": "x@y.iam.gserviceaccount.com"}))  # missing private_key
    with pytest.raises(KeyError):
        fcm.FcmAuthTokenFactory(str(bad))


# --- FCM v1 payload shape (exercises the real FcmClient.send() code path) --


@pytest.fixture
def fcm_client(service_account_path, monkeypatch):
    path, _key = service_account_path
    monkeypatch.setattr(fcm.FcmAuthTokenFactory, "token", lambda self: "fake-access-token")
    client = fcm.FcmClient(project_id="nks-talk-notify-test", service_account_path=str(path))
    yield client
    client.close()


def test_send_payload_is_data_only_no_notification_key(fcm_client, monkeypatch):
    """Android would render a plaintext OS banner from a `notification` block
    itself, before the app gets a chance to decrypt `nc-subject` -- must
    never be present."""
    captured = {}

    def fake_post(url, *, headers, json):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return httpx.Response(200, json={"name": "x"}, request=httpx.Request("POST", url))

    monkeypatch.setattr(fcm_client._client, "post", fake_post)
    result = fcm_client.send(device_token="some-fcm-token", encrypted_subject_b64="Y2lwaGVy", priority="high")

    assert result.ok
    message = captured["json"]["message"]
    assert "notification" not in message
    assert message["token"] == "some-fcm-token"
    assert message["data"] == {"nc-subject": "Y2lwaGVy"}
    assert message["android"]["priority"] == "high"
    assert captured["url"] == "https://fcm.googleapis.com/v1/projects/nks-talk-notify-test/messages:send"
    assert captured["headers"]["authorization"] == "Bearer fake-access-token"


@pytest.mark.parametrize("nc_priority,expected", [("high", "high"), ("normal", "normal"), ("anything-else", "normal")])
def test_send_priority_maps_to_android_priority(fcm_client, monkeypatch, nc_priority, expected):
    captured = {}
    monkeypatch.setattr(
        fcm_client._client,
        "post",
        lambda url, **kw: (captured.update(kw), httpx.Response(200, json={}, request=httpx.Request("POST", url)))[1],
    )
    fcm_client.send(device_token="t", encrypted_subject_b64="eA==", priority=nc_priority)
    assert captured["json"]["message"]["android"]["priority"] == expected


# --- error_code parsing (S6 for FCM: UNREGISTERED vs INVALID_ARGUMENT) ------


def _response(status_code: int, body: dict) -> httpx.Response:
    return httpx.Response(status_code, json=body, request=httpx.Request("POST", "https://fcm.googleapis.com/"))


def test_error_code_extracts_unregistered():
    resp = _response(404, {"error": {"code": 404, "status": "NOT_FOUND", "details": [{"errorCode": "UNREGISTERED"}]}})
    assert fcm._error_code(resp) == "UNREGISTERED"


def test_error_code_extracts_invalid_argument():
    resp = _response(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT", "details": [{"errorCode": "INVALID_ARGUMENT"}]}})
    assert fcm._error_code(resp) == "INVALID_ARGUMENT"


def test_error_code_none_on_success():
    assert fcm._error_code(_response(200, {"name": "projects/x/messages/1"})) is None


def test_error_code_none_when_unparseable():
    resp = httpx.Response(500, content=b"not json", request=httpx.Request("POST", "https://fcm.googleapis.com/"))
    assert fcm._error_code(resp) is None


def test_result_should_forget_device_only_for_unregistered():
    assert fcm.FcmResult(status_code=404, error_code="UNREGISTERED").should_forget_device
    assert not fcm.FcmResult(status_code=400, error_code="INVALID_ARGUMENT").should_forget_device
    assert not fcm.FcmResult(status_code=500, error_code=None).should_forget_device
