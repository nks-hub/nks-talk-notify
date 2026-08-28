from __future__ import annotations

import base64
import json
from http import HTTPStatus

import httpx
import pytest

from app import apns, fcm
from app.config import Config
from app.db import DeviceStore
from app.server import App, ReplayGuard, ReplayLease, token_kind
from .conftest import make_fake_device


class FakeApnsClient:
    def __init__(self, result: apns.ApnsResult):
        self.result = result
        self.calls: list[dict] = []

    def send(
        self,
        *,
        device_token,
        payload,
        push_type,
        priority,
        collapse_id=None,
        environment=None,
    ):
        self.calls.append(
            {
                "device_token": device_token,
                "payload": payload,
                "push_type": push_type,
                "priority": priority,
                "environment": environment,
            }
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
        trusted_proxy_ip="",
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
        "pushProvider": "apns",
        "pushEnvironment": "development",
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
    assert stored.push_provider == "apns"


@pytest.mark.parametrize("environment", ["development", "production"])
def test_register_apns_device_persists_environment(app, fake_device, environment):
    form = _register_form(fake_device)
    form["pushEnvironment"] = environment

    status, body = app.register_device(_as_qs_dict(form))

    assert status == HTTPStatus.OK
    assert body == {}
    assert app.store.get(fake_device.device_identifier).push_environment == environment


def test_register_apns_device_rejects_unknown_environment(app, fake_device):
    form = _register_form(fake_device)
    form["pushEnvironment"] = "staging"

    status, body = app.register_device(_as_qs_dict(form))

    assert status == HTTPStatus.BAD_REQUEST
    assert body == {"message": "INVALID_PUSH_ENVIRONMENT"}


def test_register_apns_device_requires_environment(app, fake_device):
    form = _register_form(fake_device)
    del form["pushEnvironment"]

    status, body = app.register_device(_as_qs_dict(form))

    assert status == HTTPStatus.BAD_REQUEST
    assert body == {"message": "INVALID_PUSH_ENVIRONMENT"}


def test_register_device_rejects_unknown_provider(app, fake_device):
    form = _register_form(fake_device)
    form["pushProvider"] = "webpush"

    status, body = app.register_device(_as_qs_dict(form))

    assert status == HTTPStatus.BAD_REQUEST
    assert body == {"message": "INVALID_PUSH_PROVIDER"}


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


def test_replay_guard_distinguishes_in_flight_and_delivered():
    guard = ReplayGuard()
    key = ("device", "signature")

    lease = guard.reserve(key)
    assert isinstance(lease, ReplayLease)
    assert guard.reserve(key) is False
    assert guard.commit(key, lease) is True
    assert guard.reserve(key) is True
    assert guard.release(key, lease) is True
    assert isinstance(guard.reserve(key), ReplayLease)


def test_replay_guard_stale_owner_cannot_mutate_replacement_lease(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("app.server.time.monotonic", lambda: now[0])
    guard = ReplayGuard(ttl_seconds=1.0)
    key = ("device", "signature")

    first_lease = guard.reserve(key)
    assert first_lease not in (None, False, True)
    now[0] += 2.0
    replacement_lease = guard.reserve(key)
    assert replacement_lease not in (None, False, True)

    assert guard.release(key, first_lease) is False
    assert guard.reserve(key) is False
    assert guard.commit(key, first_lease) is False
    assert guard.reserve(key) is False
    assert guard.commit(key, replacement_lease) is True
    assert guard.reserve(key) is True


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


def test_notifications_deletion_breaker_caps_mass_deletion(app):
    """Regression guard for the sandbox/production APNs mismatch scenario:
    every registered device looks dead at once (BadDeviceToken), and without
    a budget this would silently deregister the entire fleet in one pass."""
    devices = [make_fake_device(f'["breaker-test-{i}","1"]'.encode()) for i in range(11)]
    entries = []
    for i, device in enumerate(devices):
        app.register_device(_as_qs_dict(_register_form(device)))
        subject = FAKE_SUBJECT
        entries.append({
            "deviceIdentifier": device.device_identifier,
            "pushTokenHash": app.push_token_hash("aa" * 32),
            "subject": base64.b64encode(subject).decode(),
            "signature": device.sign_subject(subject),
            "priority": "normal",
            "type": "alert",
        })
    app.apns_client.result = apns.ApnsResult(status_code=410, apns_id=None, reason="Unregistered")

    status, body = app.send_notifications(_notif_form(entries))

    assert len(body["unknown"]) == 10  # the deletion_breaker's capacity
    assert body["failed"] == 1  # the 11th got refused, not silently forgotten
    surviving = [d for d in devices if app.store.get(d.device_identifier) is not None]
    assert len(surviving) == 1, "exactly one device should have been protected by the breaker"


def test_notifications_deletion_breaker_caps_lookup_misses(app):
    entries = [
        {
            "deviceIdentifier": f"missing-{i}",
            "pushTokenHash": "ignored",
            "subject": "ignored",
            "signature": "ignored",
        }
        for i in range(11)
    ]

    status, body = app.send_notifications(_notif_form(entries))

    assert status == HTTPStatus.OK
    assert body == {
        "unknown": [f"missing-{i}" for i in range(10)],
        "failed": 1,
    }


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


def test_notifications_transient_apns_error_can_be_retried(app, fake_device):
    app.register_device(_as_qs_dict(_register_form(fake_device)))
    app.apns_client.result = apns.ApnsResult(
        status_code=429,
        apns_id=None,
        reason="TooManyRequests",
    )
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(FAKE_SUBJECT).decode(),
        "signature": fake_device.sign_subject(FAKE_SUBJECT),
        "priority": "normal",
        "type": "alert",
    }

    first_status, first_body = app.send_notifications(_notif_form([entry]))
    app.apns_client.result = OK_RESULT
    second_status, second_body = app.send_notifications(_notif_form([entry]))

    assert first_status == HTTPStatus.OK
    assert first_body == {"unknown": [], "failed": 1}
    assert second_status == HTTPStatus.OK
    assert second_body == {"unknown": [], "failed": 0}
    assert len(app.apns_client.calls) == 2


def test_notifications_apns_transport_error_counts_failed_and_can_be_retried(
    app,
    fake_device,
):
    class UnreachableApnsClient:
        def send(self, **kwargs):
            raise httpx.ConnectTimeout("test timeout")

    app.register_device(_as_qs_dict(_register_form(fake_device)))
    app.apns_client = UnreachableApnsClient()
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash("aa" * 32),
        "subject": base64.b64encode(FAKE_SUBJECT).decode(),
        "signature": fake_device.sign_subject(FAKE_SUBJECT),
        "priority": "normal",
        "type": "alert",
    }

    first_status, first_body = app.send_notifications(_notif_form([entry]))
    retry_client = FakeApnsClient(OK_RESULT)
    app.apns_client = retry_client
    second_status, second_body = app.send_notifications(_notif_form([entry]))

    assert first_status == HTTPStatus.OK
    assert first_body == {"unknown": [], "failed": 1}
    assert second_status == HTTPStatus.OK
    assert second_body == {"unknown": [], "failed": 0}
    assert len(retry_client.calls) == 1


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
    assert body["failed"] == 5 + MAX_NOTIFICATIONS_PER_REQUEST - 10
    assert len(body["unknown"]) == 10


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
    form["pushProvider"] = "fcm"
    form.pop("pushEnvironment")
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


def test_token_kind_apns_64_chars():
    """The historical 32-byte token -- still valid, just no longer required."""
    assert token_kind("aa" * 32) == "apns"


def test_token_kind_apns_160_chars():
    """Apple doesn't guarantee 32 bytes; observed live on a real device/simulator."""
    assert token_kind("aa" * 80) == "apns"


def test_token_kind_apns_rejects_odd_hex_length():
    from app.server import _APNS_TOKEN_RE

    # 63 hex chars -- not a whole number of bytes, must not match APNs
    # specifically (an all-hex string this long still matches the FCM
    # whitelist -- that fallback is intended, this test is about APNs only)
    assert _APNS_TOKEN_RE.match("a" * 63) is None


def test_token_kind_apns_rejects_too_long():
    from app.server import _APNS_TOKEN_RE

    assert _APNS_TOKEN_RE.match("aa" * 101) is None  # 202 hex chars, over the 200 ceiling


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
        "pushProvider": "fcm",
        "deviceIdentifier": device.device_identifier,
        "deviceIdentifierSignature": device.signature,
        "userPublicKey": device.public_key_pem,
    }


def test_register_fcm_device_success(app, fake_device):
    status, body = app.register_device(_as_qs_dict(_register_fcm_form(fake_device)))
    assert status == HTTPStatus.OK
    stored = app.store.get(fake_device.device_identifier)
    assert stored.push_token == FAKE_FCM_TOKEN
    assert stored.push_provider == "fcm"


def test_register_fcm_device_rejects_environment(app, fake_device):
    form = _register_fcm_form(fake_device)
    form["pushEnvironment"] = "production"

    status, body = app.register_device(_as_qs_dict(form))

    assert status == HTTPStatus.BAD_REQUEST
    assert body == {"message": "INVALID_PUSH_ENVIRONMENT"}


def test_explicit_fcm_provider_overrides_ambiguous_hex_token(app, fake_device):
    form = _register_fcm_form(fake_device)
    form["pushToken"] = "aa" * 32
    app.register_device(_as_qs_dict(form))
    subject = FAKE_SUBJECT
    entry = {
        "deviceIdentifier": fake_device.device_identifier,
        "pushTokenHash": app.push_token_hash(form["pushToken"]),
        "subject": base64.b64encode(subject).decode(),
        "signature": fake_device.sign_subject(subject),
        "priority": "high",
        "type": "alert",
    }

    status, body = app.send_notifications(_notif_form([entry]))

    assert status == HTTPStatus.OK
    assert body == {"unknown": [], "failed": 0}
    assert app.apns_client.calls == []
    assert len(app.fcm_client.calls) == 1


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
    form = _register_form(fake_device)
    form["pushEnvironment"] = "production"
    app.register_device(_as_qs_dict(form))  # APNs-shaped token
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
    assert app.apns_client.calls[0]["environment"] == "production"


def test_notifications_routes_apns_development_production_and_legacy_together(app):
    devices = [
        make_fake_device(f'["apns-environment-{i}","1"]'.encode())
        for i in range(3)
    ]
    environments = ["development", "production", None]
    entries = []
    for index, (device, environment) in enumerate(zip(devices, environments)):
        token = f"{index + 1:02x}" * 32
        form = _register_form(device)
        form["pushToken"] = token
        if environment is None:
            form.pop("pushProvider")
            form.pop("pushEnvironment")
        else:
            form["pushEnvironment"] = environment
        app.register_device(_as_qs_dict(form))
        entries.append(
            {
                "deviceIdentifier": device.device_identifier,
                "pushTokenHash": app.push_token_hash(token),
                "subject": base64.b64encode(FAKE_SUBJECT).decode(),
                "signature": device.sign_subject(FAKE_SUBJECT),
                "priority": "normal",
                "type": "alert",
            }
        )

    status, body = app.send_notifications(_notif_form(entries))

    assert status == HTTPStatus.OK
    assert body == {"unknown": [], "failed": 0}
    assert [call["environment"] for call in app.apns_client.calls] == environments


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
