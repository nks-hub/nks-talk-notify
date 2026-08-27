"""HTTP surface for the proxy: /health, /devices, /notifications.

Deliberately built on stdlib http.server instead of a web framework — three
routes and no templating/routing needs don't justify the dependency. See
README.md "Endpointy" for the wire contract each route implements and the
exact Nextcloud source lines it was verified against.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from . import apns, crypto
from .config import Config
from .db import DeviceStore, PublicKeyMismatch

log = logging.getLogger("nks-talk-notify")

_NOTIFICATION_KEY_RE = re.compile(r"^notifications\[(\d+)\]$")

# S2: lowercase hex only -- must match exactly how the client hashes it for
# Nextcloud's own pushTokenHash, or the two never agree on the same device.
_PUSH_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")

# S4: RSA-2048 ciphertext is always exactly 256 bytes -> base64 is always
# exactly 344 chars. Anything else is malformed by definition, reject before
# spending a public-key verify on it.
_EXPECTED_SUBJECT_B64_LEN = 344

MAX_BODY_BYTES = 1024 * 1024  # S3: 1 MiB request cap
MAX_NOTIFICATIONS_PER_REQUEST = 100  # S4: cap batch size


class RateLimiter:
    """Per-key token bucket. S3: cheap DoS guard, not a precision limiter."""

    def __init__(self, capacity: int, refill_per_sec: float):
        self._capacity = capacity
        self._refill_per_sec = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()
        # ponytail: buckets are never evicted; fine for the IP cardinality a
        # single proxy sees, revisit only if that stops being true.

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self._capacity), now))
            tokens = min(self._capacity, tokens + (now - last) * self._refill_per_sec)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            return True


class ReplayGuard:
    """S5: dedupe (deviceIdentifier, signature) pairs within a TTL window.

    The native protocol has no nonce/timestamp, so a captured notification
    is replayable forever without this. A short TTL is enough since a real
    replay attempt follows shortly after the original; it doesn't need to
    catch one a week later to be useful.
    """

    def __init__(self, ttl_seconds: float = 300.0):
        self._ttl = ttl_seconds
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def seen_before(self, key: tuple[str, str]) -> bool:
        now = time.monotonic()
        with self._lock:
            # ponytail: O(n) prune on every write; fine at this proxy's scale,
            # swap for a proper TTL cache if the device count ever makes it hot.
            for stale_key in [k for k, expires_at in self._seen.items() if expires_at < now]:
                del self._seen[stale_key]
            if key in self._seen:
                return True
            self._seen[key] = now + self._ttl
            return False


class App:
    """Holds the long-lived dependencies a request handler needs."""

    def __init__(self, config: Config, store: DeviceStore, apns_client: apns.ApnsClient):
        self.config = config
        self.store = store
        self.apns_client = apns_client
        self.replay_guard = ReplayGuard()
        # S3: /devices is client-facing and cheap to abuse -> tight cap.
        # /notifications is the (trusted, but unauthenticated-if-S1-unset)
        # Nextcloud server itself and legitimately bursts -> looser cap.
        self.devices_rate_limiter = RateLimiter(capacity=20, refill_per_sec=20 / 60)
        self.notifications_rate_limiter = RateLimiter(capacity=120, refill_per_sec=120 / 60)

    def push_token_hash(self, push_token: str) -> str:
        """SHA-512 hex digest of the UTF-8 push token string.

        Contract with the mobile client: it MUST compute the same hash the
        same way (sha512 of the hex device-token string, UTF-8 encoded) when
        it sends `pushTokenHash` to Nextcloud's own /push endpoint, or the
        two systems will never agree on which device a notification is for.
        """
        return hashlib.sha512(push_token.encode("utf-8")).hexdigest()

    def register_device(self, form: dict) -> tuple[int, dict]:
        push_token = _first(form, "pushToken")
        device_identifier = _first(form, "deviceIdentifier")
        signature = _first(form, "deviceIdentifierSignature")
        public_key = _first(form, "userPublicKey")
        if not (push_token and device_identifier and signature and public_key):
            return HTTPStatus.BAD_REQUEST, {"message": "MISSING_FIELDS"}

        if not _PUSH_TOKEN_RE.match(push_token):  # S2: path-injection guard, cheap so check first
            return HTTPStatus.BAD_REQUEST, {"message": "INVALID_PUSH_TOKEN"}

        if not crypto.verify_device_identifier_signature(
            device_identifier_b64=device_identifier, signature_b64=signature, public_key_pem=public_key
        ):
            return HTTPStatus.BAD_REQUEST, {"message": "INVALID_SIGNATURE"}

        try:
            self.store.register(
                device_identifier=device_identifier,
                user_public_key=public_key,
                push_token=push_token,
                push_token_hash=self.push_token_hash(push_token),
            )
        except PublicKeyMismatch:
            # S6: 403 "unauthorized for this identifier", not 409 -- we don't
            # implement the push-v2 cloudId retry flow that 409 implies.
            return HTTPStatus.FORBIDDEN, {"message": "DEVICE_IDENTIFIER_KEY_MISMATCH"}
        return HTTPStatus.OK, {}

    def unregister_device(self, params: dict) -> tuple[int, dict]:
        device_identifier = _first(params, "deviceIdentifier")
        signature = _first(params, "deviceIdentifierSignature")
        if not (device_identifier and signature):
            return HTTPStatus.BAD_REQUEST, {"message": "MISSING_FIELDS"}

        device = self.store.get(device_identifier)
        if device is None:
            return HTTPStatus.OK, {}  # already gone, idempotent

        if not crypto.verify_device_identifier_signature(
            device_identifier_b64=device_identifier,
            signature_b64=signature,
            public_key_pem=device.user_public_key,
        ):
            return HTTPStatus.BAD_REQUEST, {"message": "INVALID_SIGNATURE"}

        self.store.delete(device_identifier)
        return HTTPStatus.OK, {}  # S7: push-v2 spec says 200, not 202

    def send_notifications(self, form: dict) -> tuple[int, dict]:
        entries = _parse_notification_entries(form)
        unknown: list[str] = []
        failed = 0

        # S4: cap batch size -- process the first N, count the rest as failed
        # so an oversized batch is visible instead of silently truncated.
        if len(entries) > MAX_NOTIFICATIONS_PER_REQUEST:
            failed += len(entries) - MAX_NOTIFICATIONS_PER_REQUEST
            entries = entries[:MAX_NOTIFICATIONS_PER_REQUEST]

        for raw in entries:
            try:
                notif = json.loads(raw)
                device_identifier = notif["deviceIdentifier"]
                push_token_hash = notif["pushTokenHash"]
                subject = notif["subject"]
                signature = notif["signature"]
                nc_priority = notif.get("priority", "normal")
                nc_type = notif.get("type", "alert")
            except (json.JSONDecodeError, KeyError, TypeError):
                failed += 1
                continue

            # "unknown" is destructive (Nextcloud deletes its record on it), so
            # a lookup miss must win over any other validation of this entry --
            # never let a malformed field turn a genuinely unknown device into
            # a "failed" instead.
            device = self.store.get(device_identifier)
            if device is None:
                unknown.append(device_identifier)
                continue

            if device.push_token_hash != push_token_hash:
                log.warning("pushTokenHash mismatch for a known deviceIdentifier")
                failed += 1
                continue

            if len(subject) != _EXPECTED_SUBJECT_B64_LEN:  # S4
                log.warning("subject has the wrong length for an RSA-2048 ciphertext")
                failed += 1
                continue

            if not crypto.verify_subject_signature(
                subject_b64=subject, signature_b64=signature, public_key_pem=device.user_public_key
            ):
                log.warning("subject signature failed verification")
                failed += 1
                continue

            if self.replay_guard.seen_before((device_identifier, signature)):  # S5
                continue  # already delivered once, silently drop the repeat

            push_type, priority = apns.push_type_and_priority(nc_type, nc_priority)
            payload = apns.build_payload(push_type=push_type, encrypted_subject_b64=subject)
            result = self.apns_client.send(
                device_token=device.push_token, payload=payload, push_type=push_type, priority=priority
            )

            if result.ok:
                continue
            if result.should_forget_device:
                log.info("APNs reason=%s for a device, forgetting it", result.reason)
                self.store.delete(device_identifier)
                unknown.append(device_identifier)
            else:
                log.warning("APNs push failed: status=%s reason=%s", result.status_code, result.reason)
                failed += 1

        return HTTPStatus.OK, {"unknown": unknown, "failed": failed}


def _first(d: dict, key: str) -> Optional[str]:
    values = d.get(key)
    if not values:
        return None
    return values[0] if isinstance(values, list) else values


def _parse_notification_entries(form: dict) -> list[str]:
    indexed: list[tuple[int, str]] = []
    for key, values in form.items():
        m = _NOTIFICATION_KEY_RE.match(key)
        if m and values:
            indexed.append((int(m.group(1)), values[0]))
    indexed.sort(key=lambda pair: pair[0])
    return [value for _, value in indexed]


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "nks-talk-notify/1.0"
        # Required for stdlib's default handle_expect_100 to fire at all (it
        # gates on protocol_version >= "HTTP/1.1"). At the HTTP/1.0 default,
        # a client/proxy sending "Expect: 100-continue" never gets a "100
        # Continue" from us and waits forever -- observed as the Apache
        # reverse proxy hanging indefinitely on a large POST, tying up a
        # shared Apache worker (DoS surface on infra this service doesn't
        # own). The stdlib default (send 100 Continue, then run do_POST,
        # which already drains + rejects oversized bodies) is enough on its
        # own; an earlier attempt to reject *before* sending 100 Continue
        # made Apache substitute its own generic error page for our 413
        # instead of relaying it -- not worth it for no functional gain.
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:  # quiet default stderr access log
            log.info("%s - %s", self.address_string(), fmt % args)

        def _send_json(self, status: int, body: dict, write_body: bool = True) -> None:
            payload = json.dumps(body).encode("utf-8") if body else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload and write_body:
                self.wfile.write(payload)
            # protocol_version is HTTP/1.1 only so stdlib will run
            # handle_expect_100 (see there) -- this service has no need for
            # keep-alive, and not closing left half-finished connections
            # hanging after every response.
            self.close_connection = True

        def _read_form(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length else b""
            return parse_qs(body.decode("utf-8"), keep_blank_values=True)

        def _drain(self, length: int, chunk_size: int = 65536) -> None:
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(chunk_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)

        def _client_ip(self) -> str:
            # Deployed behind the ISPConfig/Apache reverse proxy on gateway-host,
            # which sets X-Forwarded-For; fall back to the raw peer for
            # direct/local access (tests, health checks).
            forwarded = self.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()
            return self.client_address[0]

        def _route_get(self) -> tuple[int, dict]:
            path = urlsplit(self.path).path
            if path == "/health":
                return HTTPStatus.OK, {"status": "ok", "devices": app.store.count()}
            return HTTPStatus.NOT_FOUND, {"message": "NOT_FOUND"}

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming convention)
            self._send_json(*self._route_get())

        def do_HEAD(self) -> None:  # noqa: N802 -- health checks/monitoring probe with HEAD too
            status, body = self._route_get()
            self._send_json(status, body, write_body=False)

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path

            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > MAX_BODY_BYTES:  # S3 -- normally caught earlier by handle_expect_100, this
                self._drain(length)  # covers requests that skip Expect: 100-continue entirely
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"message": "BODY_TOO_LARGE"})
                return

            if path == "/devices":
                if not app.devices_rate_limiter.allow(self._client_ip()):  # S3
                    self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"message": "RATE_LIMITED"})
                    return
                status, body = app.register_device(self._read_form())
            elif path == "/notifications":
                key = app.config.nextcloud_subscription_key
                if key and not hmac.compare_digest(
                    self.headers.get("X-Nextcloud-Subscription-Key", ""), key
                ):  # S1
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"message": "UNAUTHORIZED"})
                    return
                if not app.notifications_rate_limiter.allow(self._client_ip()):  # S3
                    self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"message": "RATE_LIMITED"})
                    return
                status, body = app.send_notifications(self._read_form())
            else:
                status, body = HTTPStatus.NOT_FOUND, {"message": "NOT_FOUND"}
            self._send_json(status, body)

        def do_DELETE(self) -> None:  # noqa: N802
            split = urlsplit(self.path)
            if split.path != "/devices":
                self._send_json(HTTPStatus.NOT_FOUND, {"message": "NOT_FOUND"})
                return
            params = parse_qs(split.query, keep_blank_values=True)
            if not params:
                params = self._read_form()
            status, body = app.unregister_device(params)
            self._send_json(status, body)

    return Handler


def run_server(config: Config, store: DeviceStore, apns_client: apns.ApnsClient) -> ThreadingHTTPServer:
    app = App(config, store, apns_client)
    server = ThreadingHTTPServer((config.listen_host, config.listen_port), make_handler(app))
    return server
