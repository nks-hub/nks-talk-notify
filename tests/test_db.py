from __future__ import annotations

import pytest

from app.db import DeviceStore, PublicKeyMismatch


@pytest.fixture
def store(tmp_path):
    s = DeviceStore(str(tmp_path / "devices.db"))
    yield s
    s.close()


def test_register_new_device(store):
    device = store.register(
        device_identifier="id-1", user_public_key="pubkey-1", push_token="token-1", push_token_hash="hash-1"
    )
    assert device.device_identifier == "id-1"
    assert store.count() == 1


def test_register_same_identifier_updates_push_token(store):
    store.register(device_identifier="id-1", user_public_key="pubkey-1", push_token="old-token", push_token_hash="old-hash")
    updated = store.register(
        device_identifier="id-1", user_public_key="pubkey-1", push_token="new-token", push_token_hash="new-hash"
    )
    assert updated.push_token == "new-token"
    assert updated.push_token_hash == "new-hash"
    assert store.count() == 1  # still one row, not a duplicate


def test_register_same_identifier_different_key_is_rejected(store):
    store.register(device_identifier="id-1", user_public_key="pubkey-1", push_token="token-1", push_token_hash="hash-1")
    with pytest.raises(PublicKeyMismatch):
        store.register(device_identifier="id-1", user_public_key="pubkey-ATTACKER", push_token="token-x", push_token_hash="hash-x")
    # original registration must be untouched
    assert store.get("id-1").user_public_key == "pubkey-1"


def test_get_missing_device_returns_none(store):
    assert store.get("does-not-exist") is None


def test_delete_device(store):
    store.register(device_identifier="id-1", user_public_key="pubkey-1", push_token="token-1", push_token_hash="hash-1")
    assert store.delete("id-1") is True
    assert store.get("id-1") is None
    assert store.delete("id-1") is False  # idempotent, already gone
