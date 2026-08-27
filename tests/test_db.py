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


def test_concurrent_first_registrations_under_different_keys_never_corrupt(store):
    """Regression test for a real race: the key-mismatch check used to be a
    SELECT before the INSERT, outside the write lock. Two concurrent first
    registrations of the same (brand new) device_identifier under different
    keys could both pass the check, then one caller's key would land next
    to the *other* caller's push_token -- a stored row that belongs to
    neither registration. Fire N of these at once; exactly one may win, and
    whichever wins must be fully self-consistent (its own key AND its own
    token, never a mix)."""
    import threading

    n = 8
    results: list[tuple[int, bool]] = []
    results_lock = threading.Lock()
    barrier = threading.Barrier(n)

    def attempt(i: int) -> None:
        barrier.wait()  # maximize actual overlap, not just call ordering
        try:
            store.register(
                device_identifier="shared-id",
                user_public_key=f"pubkey-{i}",
                push_token=f"token-{i}",
                push_token_hash=f"hash-{i}",
            )
            ok = True
        except PublicKeyMismatch:
            ok = False
        with results_lock:
            results.append((i, ok))

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [i for i, ok in results if ok]
    assert len(winners) == 1, f"expected exactly one winner, got {winners}"
    (winner,) = winners

    stored = store.get("shared-id")
    assert stored.user_public_key == f"pubkey-{winner}"
    assert stored.push_token == f"token-{winner}"  # never another thread's token
