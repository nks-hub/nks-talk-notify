from app.server import ReplayGuard, ReplayLease


def test_distinguishes_in_flight_and_delivered():
    guard = ReplayGuard()
    key = ("device", "signature")

    lease = guard.reserve(key)
    assert isinstance(lease, ReplayLease)
    assert guard.reserve(key) is False
    assert guard.commit(key, lease) is True
    assert guard.reserve(key) is True
    assert guard.release(key, lease) is False


def test_in_flight_lease_does_not_expire(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("app.server.time.monotonic", lambda: now[0])
    guard = ReplayGuard(ttl_seconds=1.0)
    key = ("device", "signature")

    lease = guard.reserve(key)
    assert isinstance(lease, ReplayLease)
    now[0] += 2.0
    assert guard.reserve(key) is False
    assert guard.commit(key, lease) is True
    assert guard.reserve(key) is True


def test_prunes_delivered_entry_after_ttl(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("app.server.time.monotonic", lambda: now[0])
    guard = ReplayGuard(ttl_seconds=1.0)
    key = ("device", "signature")

    lease = guard.reserve(key)
    assert isinstance(lease, ReplayLease)
    assert guard.commit(key, lease) is True
    now[0] += 2.0
    assert isinstance(guard.reserve(key), ReplayLease)


def test_rejects_new_keys_at_capacity():
    guard = ReplayGuard(max_entries=2)
    first = guard.reserve(("device-1", "signature"))
    second = guard.reserve(("device-2", "signature"))
    assert isinstance(first, ReplayLease)
    assert isinstance(second, ReplayLease)

    assert guard.reserve(("device-3", "signature")) is False
    assert guard.release(("device-1", "signature"), first) is True
    assert isinstance(guard.reserve(("device-3", "signature")), ReplayLease)


def test_capacity_bounds_expiry_heap():
    guard = ReplayGuard(max_entries=2)
    for index in range(100):
        key = (f"device-{index}", "signature")
        lease = guard.reserve(key)
        if index < 2:
            assert isinstance(lease, ReplayLease)
            assert guard.commit(key, lease) is True
            assert guard.release(key, lease) is False
        else:
            assert lease is False

    assert len(guard._seen) == 2
    assert len(guard._expiries) == 2
