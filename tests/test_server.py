from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from http import HTTPStatus
from urllib.parse import urlencode

import pytest

from app import apns
from app.config import Config
from app.db import DeviceStore
from app.server import App, run_server
from .conftest import make_fake_device


class FakeApnsClient:
    def __init__(self, result: apns.ApnsResult):
        self.result = result
        self.calls: list[dict] = []

    def send(self, *, device_token, payload, push_type, priority, collapse_id=None):
        self.calls.append(
            {"device_token": device_token, "payload": payload, "push_type": push_type, "priority": priority}
        )
        return self.result


OK_RESULT = apns.ApnsResult(status_code=200, apns_id="abc", reason=None)


@pytest.fixture
def app(tmp_path):
    config = Config(
        apns_key_path="unused",
        apns_key_id="unused",
        apns_team_id="unused",
        apns_topic="com.nkshub.nextcloudtalk",
        apns_use_sandbox=True,
        db_path=str(tmp_path / "devices.db"),
        listen_host="127.0.0.1",
        listen_port=0,
    )
    store = DeviceStore(config.db_path)
    fake = FakeApnsClient(OK_RESULT)
    a = App(config, store, fake)
    yield a
    store.close()


def _register_form(device):
    return {
        "pushToken": "aa" * 32,
        "deviceIdentifier": device.device_identifier,
        "deviceIdentifierSignature": device.signature,
        "userPublicKey": device.public_key_pem,
    }


def _as_qs_dict(form: dict) -> dict:
    return {k: [v] for k, v in form.items()}


# --- registration -----------------------------------------------------------


def test_register_device_success(app, fake_device):
    status, body = app.register_device(_as_qs_dict(_register_form(fake_device)))
    assert status == HTTPStatus.OK
    assert body == {}
    stored = app.store.get(fake_device.device_identifier)
    assert stored is not None
    assert stored.push_token == "aa" * 32
    assert stored.push_token_hash == app.push_token_hash("aa" * 32)


def test_register_device_missing_field(app, fake_device):
    form = _register_form(fake_device)
    del form["userPublicKey"]
    status, body = app.register_device(_as_qs_dict(form))
    assert status == HTTPStatus.BAD_REQUEST
    assert body["message"] == "MISSING_FIELDS"


def test_register_device_invalid_signature(app, fake_device):
    form = _register_form(fake_device)
    other = make_fake_device(b'["someone-else","1"]')
    form["deviceIdentifierSignature"] = other.signature
    status, body = app.register_device(_as_qs_dict(form))
    assert status == HTTPStatus.BAD_REQUEST
    assert body["message"] == "INVALID_SIGNATURE"


def test_register_device_unrelated_signature_is_rejected(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))

    # An attacker's own (deviceIdentifier, signature, key) triple, generated
    # for a completely different preimage -- not even trying to target this
    # victim's deviceIdentifier specifically.
    attacker = make_fake_device(b'["attacker@cloud.example","1"]')
    hijack_form = {
        "pushToken": "bb" * 32,
        "deviceIdentifier": fake_device.device_identifier,  # victim's identifier
        "deviceIdentifierSignature": attacker.signature,  # ...but attacker's unrelated signature
        "userPublicKey": attacker.public_key_pem,
    }
    status, body = app.register_device(_as_qs_dict(hijack_form))
    assert status == HTTPStatus.BAD_REQUEST


def test_register_device_self_consistent_forgery_is_rejected_by_key_pin(app, fake_device):
    """The real attack a signature check alone can't stop -- and why the pin exists.

    deviceIdentifier is a public base64 digest, not a secret. Nothing stops
    an attacker from generating their OWN keypair and producing a signature
    that verifies against a *known* deviceIdentifier value with their own
    public key (self-consistent forgery, same trick documented in
    docs/architecture/push-gateway-api.md for the sibling gateway design).
    This proves that alone would NOT be caught by verify_device_identifier_signature,
    and that the first-write userPublicKey pin in DeviceStore.register() is
    the thing that actually stops the hijack once a device is registered.
    """
    from cryptography.hazmat.primitives import hashes as h
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    app.register_device(_as_qs_dict(_register_form(fake_device)))

    attacker = make_fake_device(b'["attacker@cloud.example","99"]')
    forged_digest = base64.b64decode(fake_device.device_identifier)
    forged_signature = attacker.private_key.sign(forged_digest, rsa_padding.PKCS1v15(), Prehashed(h.SHA512()))

    from app import crypto as crypto_module

    assert crypto_module.verify_device_identifier_signature(
        device_identifier_b64=fake_device.device_identifier,
        signature_b64=base64.b64encode(forged_signature).decode(),
        public_key_pem=attacker.public_key_pem,
    ), "the forged signature IS cryptographically self-consistent -- this is the point"

    hijack_form = {
        "pushToken": "bb" * 32,
        "deviceIdentifier": fake_device.device_identifier,
        "deviceIdentifierSignature": base64.b64encode(forged_signature).decode(),
        "userPublicKey": attacker.public_key_pem,
    }
    status, body = app.register_device(_as_qs_dict(hijack_form))
    assert status == HTTPStatus.CONFLICT
    assert app.store.get(fake_device.device_identifier).user_public_key == fake_device.public_key_pem


# --- unregistration ----------------------------------------------------------


def test_unregister_unknown_device_is_idempotent(app, fake_device):
    status, body = app.unregister_device(_as_qs_dict({"deviceIdentifier": fake_device.device_identifier, "deviceIdentifierSignature": fake_device.signature}))
    assert status == HTTPStatus.OK


def test_unregister_valid_signature_deletes(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    status, _ = app.unregister_device(
        _as_qs_dict({"deviceIdentifier": fake_device.device_identifier, "deviceIdentifierSignature": fake_device.signature})
    )
    assert status == HTTPStatus.ACCEPTED
    assert app.store.get(fake_device.device_identifier) is None


def test_unregister_invalid_signature_keeps_device(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    other = make_fake_device(b'["attacker","1"]')
    status, _ = app.unregister_device(
        _as_qs_dict({"deviceIdentifier": fake_device.device_identifier, "deviceIdentifierSignature": other.signature})
    )
    assert status == HTTPStatus.BAD_REQUEST
    assert app.store.get(fake_device.device_identifier) is not None


# --- notifications ------------------------------------------------------------


def _notif_form(entries: list[dict]) -> dict:
    form = {}
    for i, entry in enumerate(entries):
        form[f"notifications[{i}]"] = json.dumps(entry)
    return _as_qs_dict(form)


def test_notifications_unknown_device(app):
    status, body = app.send_notifications(
        _notif_form([{"deviceIdentifier": "nope", "pushTokenHash": "x", "subject": "eA==", "signature": "eA==", "priority": "normal", "type": "alert"}])
    )
    assert status == HTTPStatus.OK
    assert body == {"unknown": ["nope"], "failed": 0}


def test_notifications_pushtokenhash_mismatch_counts_as_failed(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    subject = b"ciphertext"
    signature = fake_device.sign_subject(subject)
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": "wrong-hash",
        "subject": base64.b64encode(subject).decode(),
        "signature": signature,
        "priority": "high",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert status == HTTPStatus.OK
    assert body == {"unknown": [], "failed": 1}


def test_notifications_bad_subject_signature_counts_as_failed(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(b"ciphertext").decode(),
        "signature": base64.b64encode(b"forged-signature-bytes-not-valid!!").decode(),
        "priority": "high",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [], "failed": 1}


def test_notifications_success_calls_apns_with_mapped_priority(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    subject = b"ciphertext-blob"
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "high",
        "type": "voip",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert status == HTTPStatus.OK
    assert body == {"unknown": [], "failed": 0}
    assert len(app.apns_client.calls) == 1
    call = app.apns_client.calls[0]
    assert call["device_token"] == "aa" * 32
    assert call["push_type"] == "voip"
    assert call["priority"] == 10
    assert call["payload"]["nc-subject"] == base64.b64encode(subject).decode()


def test_notifications_410_forgets_device_and_reports_unknown(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    app.apns_client.result = apns.ApnsResult(status_code=410, apns_id=None, reason="Unregistered")
    subject = b"x"
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "normal",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [fake_device.device_identifier], "failed": 0}
    assert app.store.get(fake_device.device_identifier) is None


def test_notifications_transient_apns_error_keeps_device_and_counts_failed(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    app.apns_client.result = apns.ApnsResult(status_code=429, apns_id=None, reason="TooManyRequests")
    subject = b"x"
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "normal",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [], "failed": 1}
    assert app.store.get(fake_device.device_identifier) is not None


def test_notifications_malformed_json_entry_counts_as_failed(app):
    form = _as_qs_dict({"notifications[0]": "{not valid json"})
    status, body = app.send_notifications(form)
    assert body == {"unknown": [], "failed": 1}


# --- real HTTP wire test (form-urlencoded, matching Nextcloud's client) -----


@pytest.fixture
def live_server(tmp_path):
    config = Config(
        apns_key_path="unused",
        apns_key_id="unused",
        apns_team_id="unused",
        apns_topic="com.nkshub.nextcloudtalk",
        apns_use_sandbox=True,
        db_path=str(tmp_path / "devices.db"),
        listen_host="127.0.0.1",
        listen_port=0,
    )
    store = DeviceStore(config.db_path)
    fake = FakeApnsClient(OK_RESULT)
    server = run_server(config, store, fake)
    server.RequestHandlerClass  # noqa: B018 - touch attribute to be explicit it's used
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}", fake
    server.shutdown()
    server.server_close()
    store.close()


def test_health_endpoint_over_http(live_server):
    base_url, _fake = live_server
    with urllib.request.urlopen(f"{base_url}/health", timeout=5) as resp:
        assert resp.status == 200
        body = json.loads(resp.read())
        assert body == {"status": "ok", "devices": 0}


def test_health_endpoint_supports_head(live_server):
    base_url, _fake = live_server
    req = urllib.request.Request(f"{base_url}/health", method="HEAD")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        assert resp.read() == b""  # HEAD must not carry a body


def test_register_and_notify_over_http_form_urlencoded(live_server, fake_device):
    base_url, fake = live_server
    form = _register_form(fake_device)
    req = urllib.request.Request(
        f"{base_url}/devices", data=urlencode(form).encode(), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200

    subject = b"real-wire-subject"
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": hash_for_wire_test(form["pushToken"]),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "high",
        "type": "alert",
    }
    notif_body = urlencode({"notifications[0]": json.dumps(entry)}).encode()
    req = urllib.request.Request(f"{base_url}/notifications", data=notif_body, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        body = json.loads(resp.read())
    assert body == {"unknown": [], "failed": 0}
    assert len(fake.calls) == 1


def hash_for_wire_test(push_token: str) -> str:
    import hashlib

    return hashlib.sha512(push_token.encode("utf-8")).hexdigest()


def test_delete_device_over_http_query_params(live_server, fake_device):
    base_url, _fake = live_server
    form = _register_form(fake_device)
    req = urllib.request.Request(
        f"{base_url}/devices", data=urlencode(form).encode(), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    urllib.request.urlopen(req, timeout=5).close()

    qs = urlencode({"deviceIdentifier": fake_device.device_identifier, "deviceIdentifierSignature": fake_device.signature})
    req = urllib.request.Request(f"{base_url}/devices?{qs}", method="DELETE")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 202


def test_unknown_route_is_404(live_server):
    base_url, _fake = live_server
    try:
        urllib.request.urlopen(f"{base_url}/nope", timeout=5)
        assert False, "expected HTTPError"
    except urllib.error.HTTPError as e:
        assert e.code == 404
