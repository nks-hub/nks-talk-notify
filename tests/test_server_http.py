from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from http import HTTPStatus
from urllib.parse import urlencode

import pytest

from app.db import DeviceStore
from app.server import run_server
from .test_server import (
    FAKE_SUBJECT,
    FakeApnsClient,
    OK_RESULT,
    _make_config,
    _register_form,
)

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


def test_register_and_notify_over_http_form_urlencoded(tmp_path, fake_device):
    # S1 is fail-closed: /notifications needs a configured key even here,
    # where the point of the test is the wire format, not the auth gate --
    # so a custom server (not the shared keyless `live_server` fixture).
    base_url, fake, server, store = _start_live_server(tmp_path, nextcloud_subscription_key="s3cr3t")
    try:
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
        req = urllib.request.Request(
            f"{base_url}/notifications", data=notif_body, method="POST",
            headers={"X-Nextcloud-Subscription-Key": "s3cr3t"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            body = json.loads(resp.read())
        assert body == {"unknown": [], "failed": 0}
        assert len(fake.calls) == 1
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def hash_for_wire_test(push_token: str) -> str:
    import hashlib

    return hashlib.sha512(push_token.encode("utf-8")).hexdigest()


def test_delete_device_rejects_query_params(live_server, fake_device):
    base_url, _fake = live_server
    form = _register_form(fake_device)
    req = urllib.request.Request(
        f"{base_url}/devices", data=urlencode(form).encode(), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    urllib.request.urlopen(req, timeout=5).close()

    qs = urlencode({"deviceIdentifier": fake_device.device_identifier, "deviceIdentifierSignature": fake_device.signature})
    req = urllib.request.Request(f"{base_url}/devices?{qs}", method="DELETE")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == HTTPStatus.BAD_REQUEST


def test_delete_device_accepts_identity_only_in_body(live_server, fake_device):
    base_url, _fake = live_server
    form = _register_form(fake_device)
    req = urllib.request.Request(
        f"{base_url}/devices", data=urlencode(form).encode(), method="POST"
    )
    urllib.request.urlopen(req, timeout=5).close()

    body = urlencode(
        {
            "deviceIdentifier": fake_device.device_identifier,
            "deviceIdentifierSignature": fake_device.signature,
        }
    ).encode()
    req = urllib.request.Request(f"{base_url}/devices", data=body, method="DELETE")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == HTTPStatus.OK
    assert store_is_empty(base_url)


def store_is_empty(base_url: str) -> bool:
    with urllib.request.urlopen(f"{base_url}/health", timeout=5) as resp:
        return json.loads(resp.read())["devices"] == 0


def test_access_log_never_contains_the_query_string(live_server, fake_device, caplog):
    """A rejected query must not expose device identity in this access log."""
    base_url, _fake = live_server
    qs = urlencode({"deviceIdentifier": fake_device.device_identifier, "deviceIdentifierSignature": fake_device.signature})
    req = urllib.request.Request(f"{base_url}/devices?{qs}", method="DELETE")
    with caplog.at_level("INFO", logger="nks-talk-notify"):
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(req, timeout=5)

    for record in caplog.records:
        message = record.getMessage()
        assert fake_device.device_identifier not in message
        assert fake_device.signature not in message
        assert "?" not in message  # no query string at all in an access-log line


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


def test_notifications_rejects_everything_when_key_is_unset(live_server):
    """S1 fail-closed: NEXTCLOUD_SUBSCRIPTION_KEY unset must mean /notifications
    rejects every caller, not that auth is simply skipped -- a misconfigured
    (missing) key must never be equivalent to "no auth needed"."""
    base_url, _fake = live_server  # default fixture: no key configured
    req = urllib.request.Request(
        f"{base_url}/notifications",
        data=urlencode({"notifications[0]": '{"deviceIdentifier":"x","pushTokenHash":"x","subject":"x","signature":"x"}'}).encode(),
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        assert False, "expected 401"
    except urllib.error.HTTPError as e:
        assert e.code == 401


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


def test_negative_content_length_is_rejected_not_read_forever(live_server):
    """A negative Content-Length makes `int()` happy but turns
    `self.rfile.read(length)` into "read until EOF" (Python's read(-1)
    semantics) -- an unauthenticated client can hold a worker thread open
    indefinitely with one request and never send a byte of body. Must be
    rejected outright, fast, before any attempt to read a body."""
    import socket
    import time
    from urllib.parse import urlsplit

    base_url, _fake = live_server
    parts = urlsplit(base_url)

    started = time.monotonic()
    with socket.create_connection((parts.hostname, parts.port), timeout=5) as sock:
        sock.sendall(
            f"POST /devices HTTP/1.1\r\n"
            f"Host: {parts.netloc}\r\n"
            f"Content-Length: -1\r\n\r\n".encode()
        )
        # deliberately send no body -- a fixed server must not wait for one
        sock.settimeout(5)
        response = b""
        while b"\r\n\r\n" not in response:
            response += sock.recv(4096)
    elapsed = time.monotonic() - started
    assert response.decode().startswith("HTTP/1.1 400")
    assert elapsed < 2, f"took {elapsed}s -- looks like it tried to read(-1) until EOF"


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


def test_client_ip_ignores_spoofed_xff_from_untrusted_peer(tmp_path, fake_device):
    """S5: X-Forwarded-For must only be trusted from the configured reverse
    proxy peer -- otherwise any caller can pick a fresh IP per request via
    the header and dodge rate limiting entirely."""
    base_url, fake, server, store = _start_live_server(tmp_path)  # trusted_proxy_ip unset -> never trust XFF
    try:
        form = _register_form(fake_device)
        data = urlencode(form).encode()
        statuses = []
        for i in range(25):  # capacity is 20
            req = urllib.request.Request(
                f"{base_url}/devices", data=data, method="POST",
                headers={"X-Forwarded-For": f"10.0.0.{i}"},  # a different "IP" every request
            )
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                statuses.append(resp.status)
            except urllib.error.HTTPError as e:
                statuses.append(e.code)
        assert 429 in statuses, "spoofed X-Forwarded-For let every request look like a fresh IP"
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_client_ip_uses_last_xff_entry_from_trusted_peer(tmp_path, fake_device):
    """S5: mod_proxy_http appends the real peer to any X-Forwarded-For the
    client already sent, it doesn't replace it -- the first entry can be
    attacker-supplied even through the real proxy. Must use the last one."""
    base_url, fake, server, store = _start_live_server(tmp_path, trusted_proxy_ip="127.0.0.1")
    try:
        form = _register_form(fake_device)
        data = urlencode(form).encode()
        statuses = []
        for i in range(25):  # capacity is 20
            # first entry (attacker-controlled) changes every request; last
            # entry (what a trusted proxy itself would have appended) stays fixed
            req = urllib.request.Request(
                f"{base_url}/devices", data=data, method="POST",
                headers={"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.9"},
            )
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                statuses.append(resp.status)
            except urllib.error.HTTPError as e:
                statuses.append(e.code)
        assert 429 in statuses, "varying the first XFF entry dodged the rate limit -- last entry isn't being used"
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_rate_limiter_evicts_idle_full_buckets(monkeypatch):
    """S5: an attacker cycling through distinct keys (or, before the XFF fix,
    distinct spoofed IPs) must not grow this dict forever."""
    from app.server import RateLimiter, _BUCKET_IDLE_SECONDS

    fake_now = [1000.0]
    monkeypatch.setattr("app.server.time.monotonic", lambda: fake_now[0])

    limiter = RateLimiter(capacity=5, refill_per_sec=1)
    limiter.allow("visitor-1")
    assert "visitor-1" in limiter._buckets

    fake_now[0] += _BUCKET_IDLE_SECONDS + 3600  # idle long enough to refill fully AND go stale

    limiter.allow("visitor-2")  # any call prunes stale buckets first
    assert "visitor-1" not in limiter._buckets, "idle, fully-refilled bucket should have been evicted"
