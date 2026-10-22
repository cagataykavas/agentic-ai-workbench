from __future__ import annotations

import json
import math
import os
import sqlite3
from pathlib import Path
from typing import Any

from src.governed_runtime import (
    ExecutionLedger,
    IdempotencyPayloadMismatchError,
    Payload,
)


class LedgerCorruptionError(RuntimeError):
    """A persisted ledger row cannot be decoded as the promised payload type."""


class SQLiteExecutionLedger(ExecutionLedger):
    """A restart-safe execution ledger backed by a local SQLite database.

    Each operation uses a short-lived connection so separate runtime instances and
    processes can share the same database file. Request-bound inserts are serialized
    with ``BEGIN IMMEDIATE`` and preserve the first successful terminal result.
    """

    def __init__(
        self,
        database: str | os.PathLike[str],
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        if os.fspath(database) == ":memory:":
            raise ValueError("SQLiteExecutionLedger requires a file-backed database")
        self.database = Path(database)
        self.timeout_seconds = timeout_seconds
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1_000)}")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_ledger (
                    key TEXT PRIMARY KEY,
                    request_sha256 TEXT,
                    output_json TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                ) STRICT
                """
            )

    @staticmethod
    def _encode(output: Payload) -> str:
        return json.dumps(
            output,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    @staticmethod
    def _decode(encoded: str) -> Payload:
        try:
            value: Any = json.loads(encoded)
        except (TypeError, json.JSONDecodeError) as exc:
            raise LedgerCorruptionError("ledger output is not valid JSON") from exc
        if not isinstance(value, dict):
            raise LedgerCorruptionError("ledger output is not a JSON object")
        return value

    def _read(self, key: str) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT request_sha256, output_json
                FROM execution_ledger
                WHERE key = ?
                """,
                (key,),
            ).fetchone()

    def get(self, key: str) -> Payload | None:
        row = self._read(key)
        return None if row is None else self._decode(row["output_json"])

    def record(self, key: str, output: Payload) -> None:
        encoded = self._encode(output)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO execution_ledger (key, output_json)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    output_json = excluded.output_json,
                    recorded_at = CURRENT_TIMESTAMP
                WHERE execution_ledger.request_sha256 IS NULL
                """,
                (key, encoded),
            )
            connection.commit()

    def get_for_request(self, key: str, request_sha256: str) -> Payload | None:
        row = self._read(key)
        if row is None:
            return None
        if row["request_sha256"] != request_sha256:
            raise IdempotencyPayloadMismatchError
        return self._decode(row["output_json"])

    def record_for_request(self, key: str, request_sha256: str, output: Payload) -> None:
        encoded = self._encode(output)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_sha256
                FROM execution_ledger
                WHERE key = ?
                """,
                (key,),
            ).fetchone()
            if row is not None:
                if row["request_sha256"] != request_sha256:
                    connection.rollback()
                    raise IdempotencyPayloadMismatchError
                connection.commit()
                return
            connection.execute(
                """
                INSERT INTO execution_ledger (key, request_sha256, output_json)
                VALUES (?, ?, ?)
                """,
                (key, request_sha256, encoded),
            )
            connection.commit()
