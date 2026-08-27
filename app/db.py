"""SQLite-backed device registry.

One row per Nextcloud `deviceIdentifier` (a base64 SHA-512 digest, see
crypto.py). `user_public_key` is pinned on first registration and never
overwritten by a later registration with a different key: that is what stops
a third party from re-registering someone else's already-known
deviceIdentifier and hijacking delivery of their notifications. A device is
free to update its `push_token` (app reinstall, APNs token rotation) as long
as it keeps proving ownership of the original private key.

# ponytail: a single process-wide lock serializes writes; SQLite in WAL mode
# handles concurrent readers fine at this scale. Upgrade to a connection pool
# / per-request connections only if this proxy ever needs more throughput
# than a single writer thread can give it.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional


class PublicKeyMismatch(ValueError):
    """Raised when a registration reuses a deviceIdentifier with a different key."""


@dataclass(frozen=True)
class Device:
    device_identifier: str
    user_public_key: str
    push_token: str
    push_token_hash: str
    created_at: str
    updated_at: str


SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_identifier TEXT PRIMARY KEY,
    user_public_key   TEXT NOT NULL,
    push_token        TEXT NOT NULL,
    push_token_hash   TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_push_token_hash ON devices(push_token_hash);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeviceStore:
    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        try:
            os.chmod(db_path, 0o600)  # S8: push tokens are sensitive, owner-only
        except OSError:
            pass  # e.g. read-only filesystem in some test setups; not fatal

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def get(self, device_identifier: str) -> Optional[Device]:
        row = self._conn.execute(
            "SELECT device_identifier, user_public_key, push_token, push_token_hash,"
            " created_at, updated_at FROM devices WHERE device_identifier = ?",
            (device_identifier,),
        ).fetchone()
        return Device(*row) if row else None

    def register(
        self, *, device_identifier: str, user_public_key: str, push_token: str, push_token_hash: str
    ) -> Device:
        """Insert a new device, or refresh push_token for an existing one.

        Raises PublicKeyMismatch if device_identifier already exists under a
        different user_public_key.

        The key check used to be a separate SELECT before this INSERT --
        racy, because two concurrent first-registrations under different
        keys could both pass the check before either had written anything
        (reproduced live). The `WHERE` on the UPSERT makes the check and the
        write one atomic statement: if the existing row's key doesn't match,
        the conflict resolution is a no-op (SQLite UPSERT semantics) and
        `rowcount` comes back 0 -- the only way this exact statement can
        affect zero rows, since a brand-new device_identifier always inserts
        directly and a matching-key conflict always updates `updated_at`.
        """
        now = _now()
        with self._write() as cur:
            cur.execute(
                """
                INSERT INTO devices (device_identifier, user_public_key, push_token, push_token_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_identifier) DO UPDATE SET
                    push_token = excluded.push_token,
                    push_token_hash = excluded.push_token_hash,
                    updated_at = excluded.updated_at
                WHERE devices.user_public_key = excluded.user_public_key
                """,
                (device_identifier, user_public_key, push_token, push_token_hash, now, now),
            )
            if cur.rowcount == 0:
                raise PublicKeyMismatch(device_identifier)
        return self.get(device_identifier)  # type: ignore[return-value]

    def delete(self, device_identifier: str) -> bool:
        with self._write() as cur:
            cur.execute("DELETE FROM devices WHERE device_identifier = ?", (device_identifier,))
            return cur.rowcount > 0

    def count(self) -> int:
        (n,) = self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()
        return int(n)
