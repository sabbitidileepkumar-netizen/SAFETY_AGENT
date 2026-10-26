from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any


@dataclass(frozen=True)
class _Entry:
    expires_at: float
    value: Any


class TTLCache:
    """Small in-memory cache; keys are digests so URLs are not retained in logs."""

    def __init__(self, ttl_seconds: int, max_entries: int = 2048) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                return None
            return entry.value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._entries) >= self._max_entries:
                oldest_key = min(self._entries, key=lambda item: self._entries[item].expires_at)
                self._entries.pop(oldest_key, None)
            self._entries[key] = _Entry(time.monotonic() + self._ttl_seconds, value)


class SQLiteTTLCache:
    """SQLite-backed cache for hashed keys and short-lived structured evidence."""

    def __init__(self, path: str, ttl_seconds: int, max_entries: int = 2048) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._lock = threading.Lock()
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_entries (
                    cache_key TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL,
                    value_json TEXT NOT NULL
                )
                """
            )

    def get(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            row = self._connection.execute(
                "SELECT expires_at, value_json FROM cache_entries WHERE cache_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return None
            if float(row[0]) <= now:
                self._connection.execute("DELETE FROM cache_entries WHERE cache_key = ?", (key,))
                self._connection.commit()
                return None
            try:
                return json.loads(row[1])
            except (TypeError, json.JSONDecodeError):
                return None

    def set(self, key: str, value: Any) -> None:
        try:
            encoded = json.dumps(value, separators=(",", ":"))
        except (TypeError, ValueError):
            return
        with self._lock:
            self._connection.execute(
                "INSERT OR REPLACE INTO cache_entries(cache_key, expires_at, value_json) VALUES (?, ?, ?)",
                (key, time.time() + self._ttl_seconds, encoded),
            )
            self._connection.execute(
                "DELETE FROM cache_entries WHERE cache_key IN "
                "(SELECT cache_key FROM cache_entries ORDER BY expires_at ASC LIMIT -1 OFFSET ?)",
                (self._max_entries,),
            )
            self._connection.commit()
