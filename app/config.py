"""Environment-driven configuration. No secrets have defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"missing required environment variable {name}")
    return value


@dataclass(frozen=True)
class Config:
    apns_key_path: str
    apns_key_id: str
    apns_team_id: str
    apns_topic: str
    apns_use_sandbox: bool
    db_path: str
    listen_host: str
    listen_port: int
    nextcloud_subscription_key: str

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            apns_key_path=_require("APNS_KEY_PATH"),
            apns_key_id=_require("APNS_KEY_ID"),
            apns_team_id=_require("APNS_TEAM_ID"),
            apns_topic=os.environ.get("APNS_TOPIC", "com.nkshub.nextcloudtalk").strip(),
            apns_use_sandbox=os.environ.get("APNS_USE_SANDBOX", "0").strip() == "1",
            db_path=os.environ.get("DB_PATH", "/data/devices.db").strip(),
            listen_host=os.environ.get("LISTEN_HOST", "0.0.0.0").strip(),
            listen_port=int(os.environ.get("LISTEN_PORT", "8080").strip()),
            # S1: matches Nextcloud's own Push::sendNotificationsToProxies
            # X-Nextcloud-Subscription-Key header, sent only when this proxy's
            # URL is registered as the server's `subscription_aware_server`.
            # Empty = unauthenticated /notifications (warn at startup, don't block).
            nextcloud_subscription_key=os.environ.get("NEXTCLOUD_SUBSCRIPTION_KEY", "").strip(),
        )
