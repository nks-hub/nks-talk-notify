"""Minimal FCM HTTP v1 provider client using a service account.

No firebase-admin SDK: a service account JSON, an RS256-signed JWT
exchanged for a short-lived OAuth2 access token (Google's server-to-server
flow: https://developers.google.com/identity/protocols/oauth2/service-account),
and a plain HTTP POST to the v1 send endpoint
(https://firebase.google.com/docs/cloud-messaging/migrate-v1).
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
from cryptography.hazmat.primitives.asymmetric import padding

from .provider_errors import ProviderResponseError

_TOKEN_URL = "https://oauth2.googleapis.com/token"
_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
_TOKEN_LIFETIME_S = 50 * 60  # Google access tokens last 1h; refresh with margin

# UNREGISTERED is FCM's exact equivalent of APNs' 410/BadDeviceToken -- the
# token is permanently gone, delete our record and tell Nextcloud to as well
# (reported via `unknown`, which is destructive -- never add anything else
# here). Everything else (INVALID_ARGUMENT, quota, transient) is `failed`:
# the registration may still be good.
_UNREGISTERED_ERROR_CODE = "UNREGISTERED"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class FcmAuthTokenFactory:
    """Exchanges a service account JSON for cached OAuth2 access tokens."""

    def __init__(self, service_account_path: str):
        with open(service_account_path, "r", encoding="utf-8") as fh:
            account = json.load(fh)
        self._client_email = account["client_email"]
        key = serialization.load_pem_private_key(account["private_key"].encode("utf-8"), password=None)
        if not hasattr(key, "sign"):
            raise ValueError("FCM_SERVICE_ACCOUNT_PATH private_key is not a signing key")
        self._private_key = key
        self._client = httpx.Client(timeout=10.0)
        self._lock = threading.Lock()
        self._cached_token: Optional[str] = None
        self._cached_at: float = 0.0

    def close(self) -> None:
        self._client.close()

    def token(self) -> str:
        with self._lock:
            now = time.time()
            if self._cached_token is not None and now - self._cached_at < _TOKEN_LIFETIME_S:
                return self._cached_token
            self._cached_token = self._mint(now)
            self._cached_at = now
            return self._cached_token

    def build_assertion(self, now: float) -> str:
        """The RS256-signed JWT itself, split out from `_mint` so it's
        testable without a real call to Google's token endpoint."""
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._client_email,
            "scope": _SCOPE,
            "aud": _TOKEN_URL,
            "iat": int(now),
            "exp": int(now) + 3600,
        }
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(claims, separators=(",", ":")).encode())
        )
        signature = self._private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return signing_input + "." + _b64url(signature)

    def _mint(self, now: float) -> str:
        response = self._client.post(
            _TOKEN_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": self.build_assertion(now),
            },
        )
        response.raise_for_status()
        payload = _json_object(response, "FCM OAuth")
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderResponseError("FCM OAuth response omitted access_token")
        return access_token


@dataclass(frozen=True)
class FcmResult:
    status_code: int
    error_code: Optional[str]  # e.g. "UNREGISTERED", "INVALID_ARGUMENT"; None on success or unparseable error

    @property
    def ok(self) -> bool:
        return self.status_code == 200

    @property
    def should_forget_device(self) -> bool:
        return self.error_code == _UNREGISTERED_ERROR_CODE


class FcmClient:
    def __init__(self, project_id: str, service_account_path: str):
        self._auth = FcmAuthTokenFactory(service_account_path)
        self._url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
        self._client = httpx.Client(timeout=10.0)

    def close(self) -> None:
        self._client.close()
        self._auth.close()

    def send(self, *, device_token: str, encrypted_subject_b64: str, priority: str) -> FcmResult:
        """`data`-only message: no `notification` block, or Android would
        render a plaintext OS banner itself and the app never gets a chance
        to decrypt `nc-subject` -- same reasoning as APNs' `mutable-content`
        + generic alert, just enforced differently since FCM has no
        equivalent of a service-extension hook for a `notification` push."""
        payload = {
            "message": {
                "token": device_token,
                "data": {"nc-subject": encrypted_subject_b64},
                "android": {"priority": "high" if priority == "high" else "normal"},
            }
        }
        headers = {"authorization": f"Bearer {self._auth.token()}"}
        response = self._client.post(self._url, headers=headers, json=payload)
        return FcmResult(status_code=response.status_code, error_code=_error_code(response))


def _error_code(response: httpx.Response) -> Optional[str]:
    if response.status_code == 200:
        return None
    payload = _json_object(response, "FCM send")
    error = payload.get("error")
    if not isinstance(error, dict):
        raise ProviderResponseError("FCM send response omitted error object")
    details = error.get("details", [])
    if not isinstance(details, list):
        raise ProviderResponseError("FCM send response has invalid error details")
    for detail in details:
        if not isinstance(detail, dict):
            raise ProviderResponseError("FCM send response has invalid error detail")
        error_code = detail.get("errorCode")
        if isinstance(error_code, str):
            return error_code
    return None


def _json_object(response: httpx.Response, provider: str) -> dict:
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise ProviderResponseError(f"{provider} response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ProviderResponseError(f"{provider} response was not a JSON object")
    return payload
