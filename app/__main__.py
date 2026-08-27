"""Entrypoint: python -m app"""
from __future__ import annotations

import logging
import signal
import sys

from . import apns, fcm
from .config import Config, ConfigError
from .db import DeviceStore
from .server import run_server


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("nks-talk-notify")

    try:
        config = Config.from_env()
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return 1

    if not config.nextcloud_subscription_key:
        log.warning(
            "NEXTCLOUD_SUBSCRIPTION_KEY is not set -- POST /notifications accepts requests from "
            "anyone who can reach this proxy. Set it once your Nextcloud server has "
            "subscription_aware_server pointed at this proxy (see README)."
        )
    if not config.apns_enabled:
        log.warning("APNs is not configured -- registering/sending to APNs tokens will fail")
    if not config.fcm_enabled:
        log.warning("FCM is not configured -- registering/sending to FCM tokens will fail")

    store = DeviceStore(config.db_path)
    apns_client = (
        apns.ApnsClient(
            key_path=config.apns_key_path,
            key_id=config.apns_key_id,
            team_id=config.apns_team_id,
            topic=config.apns_topic,
            use_sandbox=config.apns_use_sandbox,
        )
        if config.apns_enabled
        else None
    )
    fcm_client = (
        fcm.FcmClient(project_id=config.fcm_project_id, service_account_path=config.fcm_service_account_path)
        if config.fcm_enabled
        else None
    )

    server = run_server(config, store, apns_client, fcm_client)
    log.info(
        "listening on %s:%s (apns=%s fcm=%s)",
        config.listen_host,
        config.listen_port,
        config.apns_enabled,
        config.fcm_enabled,
    )

    def _shutdown(signum, frame):  # noqa: ANN001
        log.info("shutting down")
        server.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        server.serve_forever()
    finally:
        server.server_close()
        if apns_client is not None:
            apns_client.close()
        if fcm_client is not None:
            fcm_client.close()
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
