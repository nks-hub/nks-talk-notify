from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from http import HTTPStatus
from urllib.parse import urlencode

import pytest

from app import apns, fcm
from app.config import Config
from app.db import DeviceStore
from app.server import App, run_server, token_kind
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


class FakeFcmClient:
    def __init__(self, result: fcm.FcmResult):
        self.result = result
        self.calls: list[dict] = []

    def send(self, *, device_token, encrypted_subject_b64, priority):
        self.calls.append({"device_token": device_token, "encrypted_subject_b64": encrypted_subject_b64, "priority": priority})
        return self.result


OK_RESULT = apns.ApnsResult(status_code=200, apns_id="abc", reason=None)
FCM_OK_RESULT = fcm.FcmResult(status_code=200, error_code=None)

# S4: real `subject` is always base64 of a 256-byte RSA-2048 ciphertext
# (344 chars). Tests that aren't specifically about that length must use a
# correctly-sized stand-in or they'll be rejected before reaching the code
# path they mean to exercise.
FAKE_SUBJECT = bytes(range(256))

# A real APNs token is 64 lowercase hex chars ("aa"*32 elsewhere in this
# file); a plausible-shaped FCM token for tests -- long, base64url alphabet.
FAKE_FCM_TOKEN = "fcm-token_" + "Ab3" * 20


def _make_config(tmp_path, **overrides):
    defaults = dict(
        apns_key_path="unused",
        apns_key_id="unused",
        apns_team_id="unused",
        apns_topic="com.nkshub.nextcloudtalk",
        apns_use_sandbox=True,
        fcm_project_id="",
        fcm_service_account_path="",
        db_path=str(tmp_path / "devices.db"),
        listen_host="127.0.0.1",
        listen_port=0,
        nextcloud_subscription_key="",
    )
    defaults.update(overrides)
    return Config(**defaults)


@pytest.fixture
def app(tmp_path):
    config = _make_config(tmp_path)
    store = DeviceStore(config.db_path)
    fake_apns = FakeApnsClient(OK_RESULT)
    fake_fcm = FakeFcmClient(FCM_OK_RESULT)
    a = App(config, store, fake_apns, fake_fcm)
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
    assert status == HTTPStatus.FORBIDDEN  # S6: not 409 -- we don't implement the cloudId retry flow
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
    assert status == HTTPStatus.OK  # S7: push-v2 spec says 200, not 202
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
    signature = fake_device.sign_subject(FAKE_SUBJECT)
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": "wrong-hash",
        "subject": base64.b64encode(FAKE_SUBJECT).decode(),
        "signature": signature,
        "priority": "high",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert status == HTTPStatus.OK
    assert body == {"unknown": [], "failed": 1}


def test_notifications_wrong_subject_length_counts_as_failed(app, fake_device):
    """S4: base64 of an RSA-2048 ciphertext is always 344 chars, reject anything else."""
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    short_subject = b"too-short-to-be-real-rsa-ciphertext"
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(short_subject).decode(),
        "signature": fake_device.sign_subject(short_subject),
        "priority": "high",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [], "failed": 1}
    assert app.apns_client.calls == []


def test_notifications_bad_subject_signature_counts_as_failed(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(FAKE_SUBJECT).decode(),
        "signature": base64.b64encode(b"forged-signature-bytes-not-valid!!").decode(),
        "priority": "high",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [], "failed": 1}


def test_notifications_success_calls_apns_with_mapped_priority(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    subject = FAKE_SUBJECT
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


def test_notifications_replay_is_silently_dropped(app, fake_device):
    """S5: the same (deviceIdentifier, signature) pair twice must not double-send."""
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    subject = FAKE_SUBJECT
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "normal",
        "type": "alert",
    }
    status1, body1 = app.send_notifications(_notif_form([entry]))
    status2, body2 = app.send_notifications(_notif_form([entry]))  # identical replay
    assert body1 == {"unknown": [], "failed": 0}
    assert body2 == {"unknown": [], "failed": 0}  # not "failed", not "unknown" -- silently deduped
    assert len(app.apns_client.calls) == 1  # APNs only actually called once


def test_notifications_410_forgets_device_and_reports_unknown(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    app.apns_client.result = apns.ApnsResult(status_code=410, apns_id=None, reason="Unregistered")
    subject = FAKE_SUBJECT
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
    subject = FAKE_SUBJECT
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


def test_notifications_batch_over_cap_counts_extras_as_failed(app):
    """S4: a batch bigger than the cap is processed up to the cap, rest counted failed."""
    from app.server import MAX_NOTIFICATIONS_PER_REQUEST

    entries = [{"deviceIdentifier": f"nope-{i}", "pushTokenHash": "x", "subject": "x", "signature": "x"} for i in range(MAX_NOTIFICATIONS_PER_REQUEST + 5)]
    status, body = app.send_notifications(_notif_form(entries))
    assert status == HTTPStatus.OK
    assert body["failed"] == 5
    assert len(body["unknown"]) == MAX_NOTIFICATIONS_PER_REQUEST  # only the processed ones looked up


# --- push token format (S2) --------------------------------------------------


def test_register_device_rejects_non_hex_push_token(app, fake_device):
    form = _register_form(fake_device)
    form["pushToken"] = "../../etc/passwd"
    status, body = app.register_device(_as_qs_dict(form))
    assert status == HTTPStatus.BAD_REQUEST
    assert body["message"] == "INVALID_PUSH_TOKEN"


def test_register_device_uppercase_64_chars_is_valid_fcm_shape_not_rejected(app, fake_device):
    """An uppercase 64-char token doesn't match the APNs pattern (lowercase
    hex only, matching Nextcloud's own pushTokenHash regex requirements),
    but IS a plausible FCM token shape -- must not be blanket-rejected just
    for not being lowercase, or real FCM registrations would fail too."""
    form = _register_form(fake_device)
    form["pushToken"] = "AA" * 32
    status, body = app.register_device(_as_qs_dict(form))
    assert status == HTTPStatus.OK
    assert token_kind("AA" * 32) == "fcm"


def test_register_device_rejects_token_matching_neither_shape(app, fake_device):
    form = _register_form(fake_device)
    form["pushToken"] = "!!!"  # too short for FCM, wrong charset for either
    status, body = app.register_device(_as_qs_dict(form))
    assert status == HTTPStatus.BAD_REQUEST
    assert body["message"] == "INVALID_PUSH_TOKEN"


# --- token_kind() -------------------------------------------------------------


def test_token_kind_apns():
    assert token_kind("aa" * 32) == "apns"


def test_token_kind_fcm():
    assert token_kind(FAKE_FCM_TOKEN) == "fcm"


def test_token_kind_rejects_too_short_for_either():
    assert token_kind("short") is None


def test_token_kind_rejects_disallowed_characters():
    # spaces and dots are outside both whitelists, even at a plausible length
    assert token_kind("not a valid.token" + "x" * 20) is None


# --- FCM registration + dispatch ----------------------------------------------


def _register_fcm_form(device):
    return {
        "pushToken": FAKE_FCM_TOKEN,
        "deviceIdentifier": device.device_identifier,
        "deviceIdentifierSignature": device.signature,
        "userPublicKey": device.public_key_pem,
    }


def test_register_fcm_device_success(app, fake_device):
    status, body = app.register_device(_as_qs_dict(_register_fcm_form(fake_device)))
    assert status == HTTPStatus.OK
    stored = app.store.get(fake_device.device_identifier)
    assert stored.push_token == FAKE_FCM_TOKEN


def test_notifications_dispatches_fcm_device_to_fcm_client_not_apns(app, fake_device):
    app.register_device(_as_qs_dict(_register_fcm_form(fake_device)))
    subject = FAKE_SUBJECT
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash(FAKE_FCM_TOKEN),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "high",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [], "failed": 0}
    assert app.apns_client.calls == []
    assert len(app.fcm_client.calls) == 1
    call = app.fcm_client.calls[0]
    assert call["device_token"] == FAKE_FCM_TOKEN
    assert call["encrypted_subject_b64"] == base64.b64encode(subject).decode()
    assert call["priority"] == "high"


def test_notifications_fcm_unregistered_forgets_device_and_reports_unknown(app, fake_device):
    """S6-for-FCM: UNREGISTERED is the destructive one -- delete + unknown."""
    app.register_device(_as_qs_dict(_register_fcm_form(fake_device)))
    app.fcm_client.result = fcm.FcmResult(status_code=404, error_code="UNREGISTERED")
    subject = FAKE_SUBJECT
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash(FAKE_FCM_TOKEN),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "normal",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [fake_device.device_identifier], "failed": 0}
    assert app.store.get(fake_device.device_identifier) is None


def test_notifications_fcm_invalid_argument_is_failed_not_unknown(app, fake_device):
    """S6-for-FCM: INVALID_ARGUMENT must NOT be treated like UNREGISTERED --
    `unknown` is destructive, only a genuinely dead token belongs there."""
    app.register_device(_as_qs_dict(_register_fcm_form(fake_device)))
    app.fcm_client.result = fcm.FcmResult(status_code=400, error_code="INVALID_ARGUMENT")
    subject = FAKE_SUBJECT
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash(FAKE_FCM_TOKEN),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "normal",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [], "failed": 1}
    assert app.store.get(fake_device.device_identifier) is not None


def test_notifications_apns_device_still_dispatches_to_apns_client(app, fake_device):
    """Regression guard: adding FCM must not break the existing APNs path."""
    app.register_device(_as_qs_dict(_register_form(fake_device)))  # APNs-shaped token
    subject = FAKE_SUBJECT
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "high",
        "type": "alert",
    }
    status, body = app.send_notifications(_notif_form([entry]))
    assert body == {"unknown": [], "failed": 0}
    assert app.fcm_client.calls == []
    assert len(app.apns_client.calls) == 1


def test_notifications_fcm_token_without_fcm_client_configured_counts_as_failed(tmp_path, fake_device):
    """A branch being unconfigured must degrade to `failed`, never crash."""
    config = _make_config(tmp_path)
    store = DeviceStore(config.db_path)
    a = App(config, store, FakeApnsClient(OK_RESULT), fcm_client=None)
    try:
        a.register_device(_as_qs_dict(_register_fcm_form(fake_device)))
        subject = FAKE_SUBJECT
        entry = {
            "deviceIdentifier": fake_device.device_identifier,
            "pushTokenHash": a.push_token_hash(FAKE_FCM_TOKEN),
            "subject": base64.b64encode(subject).decode(),
            "signature": fake_device.sign_subject(subject),
            "priority": "normal",
            "type": "alert",
        }
        status, body = a.send_notifications(_notif_form([entry]))
        assert body == {"unknown": [], "failed": 1}
        assert a.store.get(fake_device.device_identifier) is not None  # not forgotten, just undeliverable right now
    finally:
        store.close()


# --- Config: independently optional branches ----------------------------------


def test_config_requires_at_least_one_provider(tmp_path):
    from app.config import ConfigError

    with pytest.raises(ConfigError):
        _make_config(tmp_path, apns_key_path="", apns_key_id="", apns_team_id="", fcm_project_id="", fcm_service_account_path="")


def test_config_apns_only_is_valid(tmp_path):
    config = _make_config(tmp_path)
    assert config.apns_enabled
    assert not config.fcm_enabled


def test_config_fcm_only_is_valid(tmp_path):
    config = _make_config(
        tmp_path,
        apns_key_path="",
        apns_key_id="",
        apns_team_id="",
        fcm_project_id="proj",
        fcm_service_account_path="/tmp/sa.json",
    )
    assert config.fcm_enabled
    assert not config.apns_enabled


# --- real HTTP wire test (form-urlencoded, matching Nextcloud's client) -----


def _start_live_server(tmp_path, **config_overrides):
    config = _make_config(tmp_path, **config_overrides)
    store = DeviceStore(config.db_path)
    fake = FakeApnsClient(OK_RESULT)
    server = run_server(config, store, fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    return f"http://127.0.0.1:{port}", fake, server, store


@pytest.fixture
def live_server(tmp_path):
    base_url, fake, server, store = _start_live_server(tmp_path)
    yield base_url, fake
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

    subject = FAKE_SUBJECT
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
        assert resp.status == 200  # S7


def test_unknown_route_is_404(live_server):
    base_url, _fake = live_server
    try:
        urllib.request.urlopen(f"{base_url}/nope", timeout=5)
        assert False, "expected HTTPError"
    except urllib.error.HTTPError as e:
        assert e.code == 404


# --- S1: subscription key auth on /notifications only -----------------------


def test_notifications_requires_subscription_key_when_configured(tmp_path):
    base_url, fake, server, store = _start_live_server(tmp_path, nextcloud_subscription_key="s3cr3t")
    try:
        req = urllib.request.Request(f"{base_url}/notifications", data=b"notifications%5B0%5D=x", method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            assert False, "expected 401"
        except urllib.error.HTTPError as e:
            assert e.code == 401
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_notifications_accepts_correct_subscription_key(tmp_path, fake_device):
    base_url, fake, server, store = _start_live_server(tmp_path, nextcloud_subscription_key="s3cr3t")
    try:
        req = urllib.request.Request(
            f"{base_url}/notifications",
            data=urlencode({"notifications[0]": json.dumps({"deviceIdentifier": "nope", "pushTokenHash": "x", "subject": "x", "signature": "x"})}).encode(),
            method="POST",
            headers={"X-Nextcloud-Subscription-Key": "s3cr3t"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_devices_endpoint_is_not_gated_by_subscription_key(tmp_path, fake_device):
    """S1: the header only ever comes from Nextcloud's server-to-proxy call,
    never from the client's own registration -- /devices must stay reachable."""
    base_url, fake, server, store = _start_live_server(tmp_path, nextcloud_subscription_key="s3cr3t")
    try:
        form = _register_form(fake_device)
        req = urllib.request.Request(
            f"{base_url}/devices", data=urlencode(form).encode(), method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
    finally:
        server.shutdown()
        server.server_close()
        store.close()


# --- S3: body size cap -------------------------------------------------------


def test_oversized_body_is_rejected(live_server):
    from app.server import MAX_BODY_BYTES

    base_url, _fake = live_server
    oversized = b"a" * (MAX_BODY_BYTES + 1)
    req = urllib.request.Request(f"{base_url}/devices", data=oversized, method="POST")
    try:
        urllib.request.urlopen(req, timeout=5)
        assert False, "expected 413"
    except urllib.error.HTTPError as e:
        assert e.code == 413


def test_oversized_body_drain_is_capped_not_unbounded(live_server):
    """S3 regression guard: draining the full attacker-declared Content-Length
    (rather than a fixed, own-controlled cap) reopens the DoS the cap exists
    to close -- a slow/never-finished upload would tie up a worker forever.

    Declares a huge length, sends more than _DRAIN_CAP_BYTES, and *keeps the
    connection open* (no EOF) -- an uncapped drain blocks forever waiting
    for the rest of the declared length, since nothing more is ever sent.
    A capped drain reads only its cap and responds regardless."""
    import socket
    from urllib.parse import urlsplit

    from app.server import _DRAIN_CAP_BYTES

    base_url, _fake = live_server
    parts = urlsplit(base_url)
    huge_declared_length = _DRAIN_CAP_BYTES * 4  # never actually sent

    with socket.create_connection((parts.hostname, parts.port), timeout=10) as sock:
        sock.sendall(
            f"POST /devices HTTP/1.1\r\n"
            f"Host: {parts.netloc}\r\n"
            f"Content-Length: {huge_declared_length}\r\n\r\n".encode()
        )
        sock.sendall(b"a" * (_DRAIN_CAP_BYTES + 4096))  # over the cap, still far short of the declared length
        # deliberately no shutdown/EOF -- a well-behaved capped drain must
        # not need one to respond
        sock.settimeout(5)
        try:
            response = sock.recv(4096)
        except TimeoutError:
            assert False, "no response within 5s -- drain looks unbounded (waiting for the rest of Content-Length)"
    assert response.decode().startswith("HTTP/1.1 413")


def test_oversized_body_with_expect_100_continue_gets_413_not_a_hang(live_server):
    """Regression test for a real production incident: with protocol_version
    left at the stdlib default (HTTP/1.0), handle_expect_100 is never
    invoked, so a client/proxy sending "Expect: 100-continue" never gets a
    "100 Continue" and waits forever -- reproduced live as the Apache reverse
    proxy in front of this service hanging indefinitely on a >1MiB POST,
    tying up a shared Apache worker (a DoS surface on infra this service
    doesn't own). protocol_version = "HTTP/1.1" makes stdlib answer "100
    Continue" immediately; do_POST's existing drain-then-413 logic handles
    the rest once the (still-oversized) body arrives.

    (An earlier fix rejected *before* sending 100 Continue at all, which also
    stopped the hang -- but made the live Apache proxy substitute its own
    generic error page for our 413 instead of relaying it. Letting stdlib
    send 100 Continue first and rejecting in do_POST as normal avoided that
    with no functional downside, so that's what's shipped.)
    """
    import socket
    from urllib.parse import urlsplit

    from app.server import MAX_BODY_BYTES

    base_url, _fake = live_server
    parts = urlsplit(base_url)
    oversized_len = MAX_BODY_BYTES + 1

    with socket.create_connection((parts.hostname, parts.port), timeout=5) as sock:
        sock.sendall(
            f"POST /devices HTTP/1.1\r\n"
            f"Host: {parts.netloc}\r\n"
            f"Content-Length: {oversized_len}\r\n"
            f"Expect: 100-continue\r\n\r\n".encode()
        )
        sock.settimeout(5)
        continue_line = sock.recv(4096).decode()
        assert "100 Continue" in continue_line, continue_line

        sock.sendall(b"a" * oversized_len)
        response = b""
        while b"\r\n\r\n" not in response:
            response += sock.recv(4096)
    assert response.decode().startswith("HTTP/1.1 413")


def test_devices_rate_limit_returns_429(tmp_path, fake_device):
    """S3: the bucket capacity is small enough to hit within a single test."""
    base_url, fake, server, store = _start_live_server(tmp_path)
    try:
        form = _register_form(fake_device)
        data = urlencode(form).encode()
        statuses = []
        for _ in range(25):  # capacity is 20
            req = urllib.request.Request(f"{base_url}/devices", data=data, method="POST")
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                statuses.append(resp.status)
            except urllib.error.HTTPError as e:
                statuses.append(e.code)
        assert 429 in statuses
    finally:
        server.shutdown()
        server.server_close()
        store.close()
