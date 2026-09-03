"""Environment-driven configuration. No secrets have defaults.

APNs and FCM are each independently optional -- a deployment can run with
just one provider configured. Only "neither configured" is a hard error,
since a proxy that can deliver to nothing isn't a valid deployment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    apns_key_path: str
    apns_key_id: str
    apns_team_id: str
    apns_topic: str
    apns_use_sandbox: bool
    fcm_project_id: str
    fcm_service_account_path: str
    db_path: str
    listen_host: str
    listen_port: int
    nextcloud_subscription_key: str
    trusted_proxy_ip: str
    nextcloud_subscription_keys: tuple[str, ...] = ()

    @property
    def subscription_keys(self) -> tuple[str, ...]:
        """Every key a Nextcloud server may present on POST /notifications."""
        keys = [self.nextcloud_subscription_key, *self.nextcloud_subscription_keys]
        return tuple(dict.fromkeys(key for key in keys if key))

    @property
    def apns_enabled(self) -> bool:
        return bool(self.apns_key_path and self.apns_key_id and self.apns_team_id)

    @property
    def fcm_enabled(self) -> bool:
        return bool(self.fcm_project_id and self.fcm_service_account_path)

    def __post_init__(self) -> None:
        # Enforced here, not just in from_env(), so the invariant holds no
        # matter how a Config gets built (tests construct it directly).
        if not (self.apns_enabled or self.fcm_enabled):
            raise ConfigError("neither APNs nor FCM is configured -- nothing to deliver to")

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            apns_key_path=os.environ.get("APNS_KEY_PATH", "").strip(),
            apns_key_id=os.environ.get("APNS_KEY_ID", "").strip(),
            apns_team_id=os.environ.get("APNS_TEAM_ID", "").strip(),
            apns_topic=os.environ.get("APNS_TOPIC", "com.nkshub.nextcloudtalk").strip(),
            apns_use_sandbox=os.environ.get("APNS_USE_SANDBOX", "0").strip() == "1",
            fcm_project_id=os.environ.get("FCM_PROJECT_ID", "").strip(),
            fcm_service_account_path=os.environ.get("FCM_SERVICE_ACCOUNT_PATH", "").strip(),
            db_path=os.environ.get("DB_PATH", "/data/devices.db").strip(),
            listen_host=os.environ.get("LISTEN_HOST", "0.0.0.0").strip(),
            listen_port=int(os.environ.get("LISTEN_PORT", "8080").strip()),
            # S1: matches Nextcloud's own Push::sendNotificationsToProxies
            # X-Nextcloud-Subscription-Key header, sent only when this proxy's
            # URL is registered as the server's `subscription_aware_server`.
            # Empty = /notifications rejects everyone (fail closed, warn at startup).
            nextcloud_subscription_key=os.environ.get("NEXTCLOUD_SUBSCRIPTION_KEY", "").strip(),
            # Several Nextcloud servers may share one proxy; each generates its
            # own push_subscription_key. NEXTCLOUD_SUBSCRIPTION_KEYS lists them
            # comma-separated; the singular variable stays valid on its own.
            nextcloud_subscription_keys=tuple(
                key.strip()
                for key in os.environ.get("NEXTCLOUD_SUBSCRIPTION_KEYS", "").split(",")
                if key.strip()
            ),
            # S3/S5: the one peer address allowed to set X-Forwarded-For for
            # rate-limiting purposes -- the reverse proxy in front of this
            # service. Empty = never trust X-Forwarded-For, always rate-limit
            # by the raw TCP peer (safe default; anyone able to spoof the
            # header could otherwise pick a fresh IP per request and dodge
            # every limit).
            trusted_proxy_ip=os.environ.get("TRUSTED_PROXY_IP", "").strip(),
        )
