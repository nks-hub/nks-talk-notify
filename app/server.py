"""HTTP surface for the proxy: /health, /devices, /notifications.

Deliberately built on stdlib http.server instead of a web framework — three
routes and no templating/routing needs don't justify the dependency. See
README.md "Endpointy" for the wire contract each route implements and the
exact Nextcloud source lines it was verified against.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from . import apns, crypto
from .config import Config
from .db import DeviceStore, PublicKeyMismatch

log = logging.getLogger("nks-talk-notify")

_NOTIFICATION_KEY_RE = re.compile(r"^notifications\[(\d+)\]$")


class App:
    """Holds the long-lived dependencies a request handler needs."""

    def __init__(self, config: Config, store: DeviceStore, apns_client: apns.ApnsClient):
        self.config = config
        self.store = store
        self.apns_client = apns_client

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
            return HTTPStatus.CONFLICT, {"message": "DEVICE_IDENTIFIER_KEY_MISMATCH"}
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
        return HTTPStatus.ACCEPTED, {}

    def send_notifications(self, form: dict) -> tuple[int, dict]:
        entries = _parse_notification_entries(form)
        unknown: list[str] = []
        failed = 0

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

            device = self.store.get(device_identifier)
            if device is None:
                unknown.append(device_identifier)
                continue

            if device.push_token_hash != push_token_hash:
                log.warning("pushTokenHash mismatch for a known deviceIdentifier")
                failed += 1
                continue

            if not crypto.verify_subject_signature(
                subject_b64=subject, signature_b64=signature, public_key_pem=device.user_public_key
            ):
                log.warning("subject signature failed verification")
                failed += 1
                continue

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

        def log_message(self, fmt: str, *args) -> None:  # quiet default stderr access log
            log.info("%s - %s", self.address_string(), fmt % args)

        def _send_json(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode("utf-8") if body else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload:
                self.wfile.write(payload)

        def _read_form(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length else b""
            return parse_qs(body.decode("utf-8"), keep_blank_values=True)

        def do_GET(self) -> None:  # noqa: N802 (stdlib naming convention)
            path = urlsplit(self.path).path
            if path == "/health":
                self._send_json(HTTPStatus.OK, {"status": "ok", "devices": app.store.count()})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"message": "NOT_FOUND"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            form = self._read_form()
            if path == "/devices":
                status, body = app.register_device(form)
            elif path == "/notifications":
                status, body = app.send_notifications(form)
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
