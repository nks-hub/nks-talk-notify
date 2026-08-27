"""Minimal APNs HTTP/2 provider client using token (.p8) authentication.

No certificates, no third-party push SDK: just a JWT (ES256) bearer token
built from the .p8 key, and an HTTP/2 POST per Apple's documented provider
API (https://developer.apple.com/documentation/usernotifications/
sending-notification-requests-to-apns).
"""
from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import dataclass
from typing import Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PROD_HOST = "https://api.push.apple.com"
SANDBOX_HOST = "https://api.sandbox.push.apple.com"

# Apple invalidates provider tokens older than 1h and rate-limits how often
# a new one may be minted; refresh comfortably inside that window.
_TOKEN_LIFETIME_S = 45 * 60


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class ApnsAuthTokenFactory:
    """Builds and caches the ES256 JWT APNs wants as a bearer token."""

    def __init__(self, key_path: str, key_id: str, team_id: str):
        with open(key_path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("APNS_KEY_PATH must contain an EC (.p8) private key")
        self._key = key
        self._key_id = key_id
        self._team_id = team_id
        self._lock = threading.Lock()
        self._cached_token: Optional[str] = None
        self._cached_at: float = 0.0

    def token(self) -> str:
        with self._lock:
            now = time.time()
            if self._cached_token is not None and now - self._cached_at < _TOKEN_LIFETIME_S:
                return self._cached_token
            self._cached_token = self._mint(now)
            self._cached_at = now
            return self._cached_token

    def _mint(self, now: float) -> str:
        header = {"alg": "ES256", "kid": self._key_id}
        payload = {"iss": self._team_id, "iat": int(now)}
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(payload, separators=(",", ":")).encode())
        )
        der_signature = self._key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return signing_input + "." + _b64url(raw_signature)


@dataclass(frozen=True)
class ApnsResult:
    status_code: int
    apns_id: Optional[str]
    reason: Optional[str]

    @property
    def ok(self) -> bool:
        return self.status_code == 200

    @property
    def should_forget_device(self) -> bool:
        """410 Unregistered or 400 BadDeviceToken mean the token is dead."""
        if self.status_code == 410:
            return True
        if self.status_code == 400 and self.reason == "BadDeviceToken":
            return True
        return False


class ApnsClient:
    def __init__(self, key_path: str, key_id: str, team_id: str, topic: str, use_sandbox: bool = False):
        self._auth = ApnsAuthTokenFactory(key_path, key_id, team_id)
        self._topic = topic
        host = SANDBOX_HOST if use_sandbox else PROD_HOST
        self._client = httpx.Client(base_url=host, http2=True, timeout=10.0)

    def close(self) -> None:
        self._client.close()

    def send(
        self,
        *,
        device_token: str,
        payload: dict,
        push_type: str,
        priority: int,
        collapse_id: Optional[str] = None,
    ) -> ApnsResult:
        topic = self._topic + ".voip" if push_type == "voip" else self._topic
        headers = {
            "authorization": f"bearer {self._auth.token()}",
            "apns-topic": topic,
            "apns-push-type": push_type,
            "apns-priority": str(priority),
        }
        if collapse_id:
            headers["apns-collapse-id"] = collapse_id[:64]

        response = self._client.post(f"/3/device/{device_token}", headers=headers, json=payload)
        apns_id = response.headers.get("apns-id")
        reason = None
        if response.status_code != 200:
            try:
                reason = response.json().get("reason")
            except (json.JSONDecodeError, ValueError):
                reason = None
        return ApnsResult(status_code=response.status_code, apns_id=apns_id, reason=reason)


def build_payload(*, push_type: str, encrypted_subject_b64: str) -> dict:
    """Build the APS payload. Content stays encrypted; we never see plaintext.

    - alert: generic placeholder alert + mutable-content so the app's
      Notification Service Extension decrypts `nc-subject` and replaces the
      title/body before the banner is shown.
    - voip: no displayable alert; PushKit hands this straight to the app's
      CallKit integration.
    - background: silent wake-up (e.g. Nextcloud's "delete this notification"
      push), content-available only.
    """
    if push_type == "voip":
        aps: dict = {}
    elif push_type == "background":
        aps = {"content-available": 1}
    else:
        aps = {
            "alert": {"title": "Nextcloud Talk"},
            "mutable-content": 1,
            "sound": "default",
        }
    return {"aps": aps, "nc-subject": encrypted_subject_b64}


def push_type_and_priority(nc_type: str, nc_priority: str) -> tuple[str, int]:
    """Map Nextcloud's `type`/`priority` (Push::getNotifTopicAndUrgency) to APNs."""
    push_type = {"voip": "voip", "background": "background"}.get(nc_type, "alert")
    priority = 10 if nc_priority == "high" else 5
    return push_type, priority
