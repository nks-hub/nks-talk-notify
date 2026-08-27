"""Entrypoint: python -m app"""
from __future__ import annotations

import logging
import signal
import sys

from . import apns
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

    store = DeviceStore(config.db_path)
    apns_client = apns.ApnsClient(
        key_path=config.apns_key_path,
        key_id=config.apns_key_id,
        team_id=config.apns_team_id,
        topic=config.apns_topic,
        use_sandbox=config.apns_use_sandbox,
    )

    server = run_server(config, store, apns_client)
    log.info("listening on %s:%s (topic=%s sandbox=%s)", config.listen_host, config.listen_port, config.apns_topic, config.apns_use_sandbox)

    def _shutdown(signum, frame):  # noqa: ANN001
        log.info("shutting down")
        server.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        server.serve_forever()
    finally:
        server.server_close()
        apns_client.close()
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
