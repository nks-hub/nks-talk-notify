"""HTTP surface for the proxy: /health, /devices, /notifications.

Deliberately built on stdlib http.server instead of a web framework — three
routes and no templating/routing needs don't justify the dependency. See
README.md "Endpointy" for the wire contract each route implements and the
exact Nextcloud source lines it was verified against.
"""
from __future__ import annotations

import hashlib
import heapq
import hmac
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlsplit

import httpx

from . import apns, crypto, fcm
from .config import Config
from .db import Device, DeviceStore, PublicKeyMismatch
from .provider_errors import ProviderResponseError

log = logging.getLogger("nks-talk-notify")

_NOTIFICATION_KEY_RE = re.compile(r"^notifications\[(\d+)\]$")

# S2: charset stays strict (lowercase hex only -- matches how the client
# hashes it for Nextcloud's own pushTokenHash, and closes the path-injection
# vector into apns.py's f"/3/device/{device_token}"), but the length must
# NOT be pinned to the historical 32-byte/64-char token: Apple's own docs
# say device token length isn't guaranteed stable, and real devices have
# been observed handing back 160-char (80-byte) tokens. 64-200 hex chars,
# always an even count of hex digits (whole bytes).
_APNS_TOKEN_RE = re.compile(r"^(?:[0-9a-f]{2}){32,100}$")
# FCM registration tokens have no Google-documented fixed length or exact
# charset, but are always base64url-ish (real-world tokens use this alphabet,
# never APNs' plain lowercase hex) -- a strict whitelist, not "anything that
# isn't an APNs token", since this also gets sent on to Google's API.
_FCM_TOKEN_RE = re.compile(r"^[A-Za-z0-9_:-]{32,4096}$")


def token_kind(push_token: str) -> Optional[str]:
    """Infer a provider for registrations predating pushProvider."""
    if _APNS_TOKEN_RE.match(push_token):
        return "apns"
    if _FCM_TOKEN_RE.match(push_token):
        return "fcm"
    return None

# S4: RSA-2048 ciphertext is always exactly 256 bytes -> base64 is always
# exactly 344 chars. Anything else is malformed by definition, reject before
# spending a public-key verify on it.
_EXPECTED_SUBJECT_B64_LEN = 344

MAX_BODY_BYTES = 1024 * 1024  # S3: 1 MiB request cap
MAX_NOTIFICATIONS_PER_REQUEST = 100  # S4: cap batch size
# Hard, own-controlled ceiling for draining a rejected oversized body -- see
# Handler._drain(). Independent of MAX_BODY_BYTES: this exists to let the
# reverse proxy finish relaying a realistically-oversized body so it can
# deliver our 413 cleanly, not to define what we accept.
_DRAIN_CAP_BYTES = 8 * 1024 * 1024
_MAX_REPLAY_ENTRIES = 16_384


_BUCKET_IDLE_SECONDS = 3600.0  # S5: forget a fully-refilled bucket after this long unused


class RateLimiter:
    """Per-key token bucket. S3: cheap DoS guard, not a precision limiter."""

    def __init__(self, capacity: int, refill_per_sec: float):
        self._capacity = capacity
        self._refill_per_sec = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            # S5: without this, a caller cycling through distinct keys grows
            # this dict forever -- previously reachable by spoofing
            # X-Forwarded-For (now closed, see _client_ip), kept as a bound
            # here too since nothing should trust that fix alone.
            # ponytail: O(n) prune on every call, same tradeoff ReplayGuard
            # already makes -- fine at this proxy's scale. A bucket only
            # goes stale once it's idle long enough to have refilled to full
            # capacity (computed here, not read from the stored -- possibly
            # not-yet-refilled -- token count), so evicting one is exactly
            # equivalent to it never having existed.
            stale_cutoff = now - _BUCKET_IDLE_SECONDS
            stale_keys = [
                k
                for k, (tokens, last) in self._buckets.items()
                if last < stale_cutoff and min(self._capacity, tokens + (now - last) * self._refill_per_sec) >= self._capacity
            ]
            for stale_key in stale_keys:
                del self._buckets[stale_key]

            tokens, last = self._buckets.get(key, (float(self._capacity), now))
            tokens = min(self._capacity, tokens + (now - last) * self._refill_per_sec)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            return True


@dataclass(frozen=True)
class ReplayLease:
    generation: int


@dataclass
class _ReplayEntry:
    lease: ReplayLease
    delivered: bool = False
    expires_at: Optional[float] = None


class ReplayGuard:
    """S5: dedupe (deviceIdentifier, signature) pairs within a TTL window.

    The native protocol has no nonce/timestamp, so a captured notification
    is replayable forever without this. A short TTL is enough since a real
    replay attempt follows shortly after the original; it doesn't need to
    catch one a week later to be useful.
    """

    def __init__(
        self,
        ttl_seconds: float = 300.0,
        max_entries: int = _MAX_REPLAY_ENTRIES,
    ):
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError("Replay guard limits must be positive")
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._seen: dict[tuple[str, str], _ReplayEntry] = {}
        self._expiries: list[tuple[float, int, tuple[str, str]]] = []
        self._generation = 0
        self._lock = threading.Lock()

    def reserve(self, key: tuple[str, str]) -> ReplayLease | bool:
        """Atomically reserve a delivery key.

        Returns an opaque lease for a new reservation, False while another
        request owns an in-flight lease or the guard is at capacity, and True
        after a successful delivery. A failed provider attempt releases only
        its own lease so an upstream retry is neither suppressed nor corrupted
        by an expired owner.
        """
        now = time.monotonic()
        with self._lock:
            self._prune_delivered(now)
            current = self._seen.get(key)
            if current is not None:
                return current.delivered
            if len(self._seen) >= self._max_entries:
                return False
            self._generation += 1
            lease = ReplayLease(self._generation)
            self._seen[key] = _ReplayEntry(lease=lease)
            return lease

    def commit(self, key: tuple[str, str], lease: ReplayLease) -> bool:
        with self._lock:
            current = self._seen.get(key)
            if current is None or current.lease is not lease:
                return False
            if current.delivered:
                return True
            current.delivered = True
            current.expires_at = time.monotonic() + self._ttl
            heapq.heappush(
                self._expiries,
                (current.expires_at, lease.generation, key),
            )
            return True

    def release(self, key: tuple[str, str], lease: ReplayLease) -> bool:
        with self._lock:
            current = self._seen.get(key)
            if (
                current is None
                or current.lease is not lease
                or current.delivered
            ):
                return False
            self._seen.pop(key, None)
            return True

    def _prune_delivered(self, now: float) -> None:
        while self._expiries and self._expiries[0][0] < now:
            expires_at, generation, key = heapq.heappop(self._expiries)
            current = self._seen.get(key)
            if (
                current is not None
                and current.delivered
                and current.expires_at == expires_at
                and current.lease.generation == generation
            ):
                del self._seen[key]


class App:
    """Holds the long-lived dependencies a request handler needs."""

    def __init__(
        self,
        config: Config,
        store: DeviceStore,
        apns_client: Optional[apns.ApnsClient] = None,
        fcm_client: Optional[fcm.FcmClient] = None,
    ):
        self.config = config
        self.store = store
        self.apns_client = apns_client
        self.fcm_client = fcm_client
        self.replay_guard = ReplayGuard()
        # S3: /devices is client-facing and cheap to abuse -> tight cap.
        # /notifications is the (trusted, but unauthenticated-if-S1-unset)
        # Nextcloud server itself and legitimately bursts -> looser cap.
        self.devices_rate_limiter = RateLimiter(capacity=20, refill_per_sec=20 / 60)
        self.notifications_rate_limiter = RateLimiter(capacity=120, refill_per_sec=120 / 60)
        # Circuit breaker on destructive dead-token cleanup, not another
        # per-IP limiter -- this one's keyed by a single fixed string, a
        # shared budget across the whole fleet. Apple's BadDeviceToken (and
        # FCM's UNREGISTERED) mean "delete this device" in the normal case
        # (uninstalled app, expired token), which trickles in slowly. But
        # they're also *exactly* what legacy APNs registrations get back if
        # someone flips their APNS_USE_SANDBOX fallback against the
        # environment that issued those tokens. Explicit per-device
        # environments prevent this for current clients, but Apple still
        # cannot distinguish a legacy mismatch from a real uninstall.
        # Reusing RateLimiter as a budget (not a per-caller gate)
        # means a burst of "everyone just went dead" -- however many
        # separate /notifications calls it arrives across -- runs out of
        # budget and trips, instead of deleting the whole fleet. 10/hour is
        # generous for organic churn on a proxy this size and tight for an
        # environment-mismatch incident, which tries to delete everyone
        # within the first notification round after the flip.
        self.deletion_breaker = RateLimiter(capacity=10, refill_per_sec=10 / 3600)

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
        push_provider = _first(form, "pushProvider")
        push_environment = _first(form, "pushEnvironment")
        voip_token = _first(form, "voipToken")
        if not (push_token and device_identifier and signature and public_key):
            return HTTPStatus.BAD_REQUEST, {"message": "MISSING_FIELDS"}

        if push_provider not in (None, "apns", "fcm"):
            return HTTPStatus.BAD_REQUEST, {"message": "INVALID_PUSH_PROVIDER"}

        kind = push_provider or token_kind(push_token)
        valid_token = (
            _APNS_TOKEN_RE.match(push_token)
            if kind == "apns"
            else _FCM_TOKEN_RE.match(push_token) if kind == "fcm" else None
        )
        if valid_token is None:  # S2: path-injection guard, cheap so check first
            return HTTPStatus.BAD_REQUEST, {"message": "INVALID_PUSH_TOKEN"}
        valid_apns_environments = (
            apns.DEVELOPMENT_ENVIRONMENT,
            apns.PRODUCTION_ENVIRONMENT,
        )
        if kind == "apns" and (
            push_environment not in valid_apns_environments
            and not (push_provider is None and push_environment is None)
        ):
            return HTTPStatus.BAD_REQUEST, {"message": "INVALID_PUSH_ENVIRONMENT"}
        if kind == "fcm" and push_environment is not None:
            return HTTPStatus.BAD_REQUEST, {"message": "INVALID_PUSH_ENVIRONMENT"}
        # PushKit has a device token of its own, in the same shape as the
        # ordinary APNs one and never equal to it. Only iOS has one at all.
        if voip_token is not None and (
            kind != "apns" or not _APNS_TOKEN_RE.match(voip_token)
        ):
            return HTTPStatus.BAD_REQUEST, {"message": "INVALID_VOIP_TOKEN"}

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
                push_provider=push_provider,
                push_environment=push_environment,
                voip_token=voip_token,
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
                if self.deletion_breaker.allow("fleet"):
                    unknown.append(device_identifier)
                else:
                    log.error(
                        "deletion breaker tripped -- refusing another destructive lookup-miss response"
                    )
                    failed += 1
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

            replay_key = (device_identifier, signature)
            replay_state = self.replay_guard.reserve(replay_key)  # S5
            if replay_state is True:
                continue  # already delivered once, silently drop the repeat
            if replay_state is False:
                failed += 1  # another request is still delivering it
                continue
            replay_lease = replay_state

            try:
                kind = device.push_provider or token_kind(device.push_token)
                if kind == "apns":
                    forget = self._send_via_apns(device, subject, nc_type, nc_priority)
                elif kind == "fcm":
                    forget = self._send_via_fcm(device.push_token, subject, nc_priority)
                else:
                    forget = None  # defensive: registration already rejects anything else
            except (httpx.HTTPError, ProviderResponseError) as exc:
                log.warning(
                    "push provider request failed: provider=%s error=%s",
                    kind,
                    type(exc).__name__,
                )
                forget = None
            except Exception:
                self.replay_guard.release(replay_key, replay_lease)
                raise

            if forget is None:
                self.replay_guard.release(replay_key, replay_lease)
                failed += 1
            elif forget:
                try:
                    if self.deletion_breaker.allow("fleet"):
                        self.store.delete(device_identifier)
                        unknown.append(device_identifier)
                    else:
                        log.error(
                            "deletion breaker tripped -- refusing to forget a dead-token registration "
                            "(deletions exceeded the "
                            "hourly budget). Likely cause: the APNs environment or FCM credentials don't match what "
                            "your devices actually registered under -- check that before assuming devices are gone."
                        )
                        failed += 1
                finally:
                    self.replay_guard.release(replay_key, replay_lease)
            else:
                if not self.replay_guard.commit(replay_key, replay_lease):
                    log.error("replay lease state was lost after provider acceptance")
                    failed += 1

        return HTTPStatus.OK, {"unknown": unknown, "failed": failed}

    def _send_via_apns(
        self,
        device: Device,
        subject: str,
        nc_type: str,
        nc_priority: str,
    ) -> Optional[bool]:
        """Returns True if the device should be forgotten, False if delivered
        fine, None on failure that doesn't warrant forgetting it (or if APNs
        isn't configured -- own env vars unset while an APNs token is somehow
        registered, e.g. after a config change)."""
        if self.apns_client is None:
            log.warning("APNs token needs sending but APNs is not configured")
            return None
        push_type, priority = apns.push_type_and_priority(nc_type, nc_priority)
        # A VoIP push goes to PushKit, which has a device token of its own and
        # the `.voip` topic; sending one to the ordinary token is refused as
        # DeviceTokenNotForTopic. A client without PushKit (every client before
        # this field existed, and every non-iOS one) still has to hear about a
        # call, so it gets the ordinary alert rather than nothing.
        if push_type == "voip" and not device.voip_token:
            push_type = "alert"
        device_token = device.voip_token if push_type == "voip" else device.push_token
        payload = apns.build_payload(push_type=push_type, encrypted_subject_b64=subject)
        result = self.apns_client.send(
            device_token=device_token,
            payload=payload,
            push_type=push_type,
            priority=priority,
            environment=device.push_environment,
        )
        if result.ok:
            return False
        if result.should_forget_device:
            if push_type == "voip":
                # Only the PushKit registration is gone; alert delivery to this
                # device is untouched, so the row stays and Nextcloud keeps it.
                log.info("APNs reason=%s for a VoIP token, forgetting only that", result.reason)
                self.store.clear_voip_token(device.device_identifier)
                return None
            log.info("APNs reason=%s for a device, forgetting it", result.reason)
            return True
        log.warning("APNs push failed: status=%s reason=%s", result.status_code, result.reason)
        return None

    def _send_via_fcm(self, device_token: str, subject: str, nc_priority: str) -> Optional[bool]:
        if self.fcm_client is None:
            log.warning("FCM token needs sending but FCM is not configured")
            return None
        result = self.fcm_client.send(device_token=device_token, encrypted_subject_b64=subject, priority=nc_priority)
        if result.ok:
            return False
        if result.should_forget_device:
            log.info("FCM error_code=%s for a device, forgetting it", result.error_code)
            return True
        log.warning("FCM push failed: status=%s error_code=%s", result.status_code, result.error_code)
        return None


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
        # stdlib StreamRequestHandler applies this to the underlying socket
        # (settimeout in setup(), handled via handle_timeout()/socket.timeout
        # everywhere the connection blocks -- reading the request line AND
        # reading a body). Without it, a client that opens a connection and
        # never finishes sending holds a thread forever; ThreadingHTTPServer
        # has no cap on concurrent threads, so that's an unbounded resource
        # hold from a single slow/malicious client. 10s is generous for a
        # real mobile network, short enough that abuse self-heals fast.
        timeout = 10

        def log_message(self, fmt: str, *args) -> None:  # quiet default stderr access log
            log.info("%s - %s", self.address_string(), fmt % args)

        def log_request(self, code="-", size="-") -> None:
            # Overridden (not just log_message) because stdlib's default
            # builds the line from self.requestline, the raw request line AS
            # SENT BY THE CLIENT -- for DELETE /devices?deviceIdentifier=...
            # &deviceIdentifierSignature=..., that's a device's registration
            # credentials sitting in plaintext in every log this line
            # reaches (container stdout, the reverse proxy's access log,
            # their rotated copies). Log path only, never the query string.
            path = urlsplit(self.path).path
            self.log_message('"%s %s %s" %s %s', self.command, path, self.request_version, str(code), str(size))

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

        def _content_length(self) -> Optional[int]:
            """Validated Content-Length, or None if missing/malformed/negative.

            `int()` alone accepts "-1" happily, and `self.rfile.read(-1)`
            then means "read until EOF" instead of "no body" -- a client
            sending a negative Content-Length turns S3's own size check
            (`length > MAX_BODY_BYTES`, false for -1) into an unbounded read
            that holds the thread until the peer closes on its own, i.e.
            never. Centralized so every caller that reads a request body
            goes through the same validation, not just the one a report
            happened to name.
            """
            raw = self.headers.get("Content-Length")
            if raw is None:
                return 0
            try:
                length = int(raw)
            except ValueError:
                return None
            return length if length >= 0 else None

        def _validate_length(self) -> tuple[bool, int]:
            """Checks Content-Length and, if it's oversized, rejects with 413
            (draining what the proxy is trying to send, see _drain). Returns
            (False, 0) with the error response already sent, or (True, length)."""
            length = self._content_length()
            if length is None:
                self._send_json(HTTPStatus.BAD_REQUEST, {"message": "INVALID_CONTENT_LENGTH"})
                return False, 0
            if length > MAX_BODY_BYTES:  # S3
                self._drain(length)
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"message": "BODY_TOO_LARGE"})
                return False, 0
            return True, length

        def _read_form(self, length: int) -> dict:
            body = self.rfile.read(length) if length else b""
            return parse_qs(body.decode("utf-8"), keep_blank_values=True)

        def _drain(self, length: int, cap: int = _DRAIN_CAP_BYTES) -> None:
            # Only ever read up to `cap` regardless of the declared
            # Content-Length: draining the full attacker-declared length
            # (possibly slow-trickled) would tie up this worker for as long
            # as they feel like sending, which is exactly the resource
            # exhaustion S3 exists to prevent -- `cap` is a fixed constant
            # WE control, never the client's own claim.
            #
            # It has to be generous, not token-sized: the Apache/ISPConfig
            # reverse proxy in front of this service writes the whole
            # request body to us before it will accept any response as
            # valid. If we stop reading before it finishes writing (its
            # buffer fills, our TCP receive window closes), it treats that
            # as a failed upstream and returns its own 502 instead of
            # relaying our 413 -- reproduced live with a too-small cap.
            # `cap` still bounds the damage a hostile Content-Length can do;
            # the rate limiter above bounds how often one source can repeat it.
            self.rfile.read(min(length, cap))

        def _client_ip(self) -> str:
            # Only trust X-Forwarded-For when it's the known reverse proxy
            # (TRUSTED_PROXY_IP, e.g. 192.0.2.10 on the reference
            # deployment) on the wire directly -- anyone else can put
            # whatever they like in that header, and if we believed it
            # unconditionally, a single attacker could pick a fresh IP for
            # every request and dodge the rate limiters entirely. Take the
            # *last* entry, not the first: mod_proxy_http appends the real
            # peer to whatever X-Forwarded-For the client already sent
            # rather than replacing it, so the first entry can be
            # attacker-supplied even when the request did come through our
            # own proxy.
            trusted_proxy = app.config.trusted_proxy_ip
            if trusted_proxy and self.client_address[0] == trusted_proxy:
                forwarded = self.headers.get("X-Forwarded-For")
                if forwarded:
                    return forwarded.split(",")[-1].strip()
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

            ok, length = self._validate_length()  # S3, and rejects a bad/negative Content-Length outright
            if not ok:
                return

            if path == "/devices":
                if not app.devices_rate_limiter.allow(self._client_ip()):  # S3
                    self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"message": "RATE_LIMITED"})
                    return
                status, body = app.register_device(self._read_form(length))
            elif path == "/notifications":
                # S1, fail closed: an unset key must REJECT every request,
                # not accept them. The old "only check if key is set" logic
                # made a missing/misconfigured key equivalent to no auth at
                # all -- a misconfiguration silently becoming an open relay.
                # /devices doesn't get this: it's never the caller that would
                # send this header (Nextcloud is), so it stays gated purely
                # by the deviceIdentifier signature + key pin as designed.
                presented = self.headers.get("X-Nextcloud-Subscription-Key", "")
                keys = app.config.subscription_keys
                if not keys or not any(hmac.compare_digest(presented, key) for key in keys):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"message": "UNAUTHORIZED"})
                    return
                if not app.notifications_rate_limiter.allow(self._client_ip()):  # S3
                    self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"message": "RATE_LIMITED"})
                    return
                status, body = app.send_notifications(self._read_form(length))
            else:
                status, body = HTTPStatus.NOT_FOUND, {"message": "NOT_FOUND"}
            self._send_json(status, body)

        def do_DELETE(self) -> None:  # noqa: N802
            split = urlsplit(self.path)
            if split.path != "/devices":
                self._send_json(HTTPStatus.NOT_FOUND, {"message": "NOT_FOUND"})
                return

            if split.query:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"message": "DEVICE_IDENTITY_MUST_BE_IN_BODY"},
                )
                return

            ok, length = self._validate_length()  # same guard POST gets -- this read a body unchecked before
            if not ok:
                return
            if not app.devices_rate_limiter.allow(self._client_ip()):  # same bucket as POST /devices, same resource
                self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"message": "RATE_LIMITED"})
                return

            params = self._read_form(length)
            status, body = app.unregister_device(params)
            self._send_json(status, body)

    return Handler


def run_server(
    config: Config,
    store: DeviceStore,
    apns_client: Optional[apns.ApnsClient] = None,
    fcm_client: Optional[fcm.FcmClient] = None,
) -> ThreadingHTTPServer:
    app = App(config, store, apns_client, fcm_client)
    server = ThreadingHTTPServer((config.listen_host, config.listen_port), make_handler(app))
    return server
