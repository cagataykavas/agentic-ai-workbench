from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from src.governed_runtime import (
    ExecutionLedger,
    IdempotencyPayloadMismatchError,
    Payload,
)
from src.reconciliation import (
    ReceiptAuthenticator,
    ReconciliationReceipt,
    RetryAuthorizationReceipt,
)


class LedgerCorruptionError(RuntimeError):
    """A persisted ledger row cannot be decoded as the promised payload type."""


class StaleFencingTokenError(RuntimeError):
    """A worker no longer owns the claim it is trying to mutate."""


class RetryBudgetExhaustedError(RuntimeError):
    """An unknown claim has consumed its persisted retry allowance."""

    def __init__(self, retry_count: int, retry_limit: int) -> None:
        self.retry_count = retry_count
        self.retry_limit = retry_limit
        super().__init__(f"retry budget exhausted ({retry_count}/{retry_limit})")


class ClaimDisposition(StrEnum):
    ACQUIRED = "acquired"
    REPLAYED = "replayed"
    BUSY = "busy"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ExecutionClaim:
    disposition: ClaimDisposition
    fencing_token: int | None = None
    lease_expires_at_ms: int | None = None
    output: Payload | None = None
    retry_count: int | None = None
    retry_limit: int | None = None


@runtime_checkable
class ClaimingExecutionLedger(Protocol):
    def claim_for_request(
        self,
        key: str,
        request_sha256: str,
        *,
        lease_seconds: float,
    ) -> ExecutionClaim: ...

    def complete_claim(
        self,
        key: str,
        request_sha256: str,
        fencing_token: int,
        output: Payload,
    ) -> None: ...

    def abandon_claim(self, key: str, request_sha256: str, fencing_token: int) -> None: ...

    def mark_claim_unknown(self, key: str, request_sha256: str, fencing_token: int) -> None: ...


_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAX_LEASE_SECONDS = 3_600.0
_MAX_RETRY_ATTEMPTS = 100
_LEGACY_RETRY_LIMIT = 3


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
        max_retry_attempts: int = _LEGACY_RETRY_LIMIT,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        if os.fspath(database) == ":memory:":
            raise ValueError("SQLiteExecutionLedger requires a file-backed database")
        if type(max_retry_attempts) is not int or not 0 <= max_retry_attempts <= _MAX_RETRY_ATTEMPTS:
            raise ValueError("max_retry_attempts must be an integer in [0, 100]")
        self.database = Path(database)
        self.timeout_seconds = timeout_seconds
        self.max_retry_attempts = max_retry_attempts
        self._clock = clock
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
            connection.execute("BEGIN IMMEDIATE")
            try:
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
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS execution_claims (
                        key TEXT PRIMARY KEY,
                        request_sha256 TEXT NOT NULL,
                        fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
                        lease_expires_at_ms INTEGER NOT NULL,
                        state TEXT NOT NULL CHECK (state IN ('running', 'unknown')),
                        retry_count INTEGER NOT NULL DEFAULT 0
                            CHECK (retry_count >= 0 AND retry_count <= retry_limit),
                        retry_limit INTEGER NOT NULL DEFAULT 3
                            CHECK (retry_limit >= 0 AND retry_limit <= 100),
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ) STRICT
                    """
                )
                columns = {
                    str(row["name"]) for row in connection.execute("PRAGMA table_info(execution_claims)")
                }
                if "retry_count" not in columns:
                    connection.execute(
                        """
                        ALTER TABLE execution_claims
                        ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0
                            CHECK (retry_count >= 0 AND retry_count <= 100)
                        """
                    )
                if "retry_limit" not in columns:
                    connection.execute(
                        f"""
                        ALTER TABLE execution_claims
                        ADD COLUMN retry_limit INTEGER NOT NULL DEFAULT {_LEGACY_RETRY_LIMIT}
                            CHECK (retry_limit >= 0 AND retry_limit <= 100)
                        """
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    @staticmethod
    def _validate_claim_identity(key: str, request_sha256: str) -> None:
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 512:
            raise ValueError("claim key must be 1-512 UTF-8 bytes")
        if not isinstance(request_sha256, str) or not _SHA256_PATTERN.fullmatch(request_sha256):
            raise ValueError("request_sha256 must be a lowercase SHA-256 digest")

    @staticmethod
    def _validate_fencing_token(fencing_token: int, *, may_increment: bool = False) -> None:
        maximum = 9_223_372_036_854_775_806 if may_increment else 9_223_372_036_854_775_807
        if type(fencing_token) is not int or not 0 < fencing_token <= maximum:
            raise ValueError("fencing_token must be a positive SQLite integer")

    def _lease_expiry_ms(self, lease_seconds: float) -> tuple[int, int]:
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(lease_seconds)
            or not 0 < lease_seconds <= _MAX_LEASE_SECONDS
        ):
            raise ValueError("lease_seconds must be finite and in (0, 3600]")
        now_ms = math.floor(self._clock() * 1_000)
        return now_ms, now_ms + max(1, math.floor(lease_seconds * 1_000))

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
            if connection.execute(
                "SELECT 1 FROM execution_claims WHERE key = ?",
                (key,),
            ).fetchone():
                connection.rollback()
                raise StaleFencingTokenError("active claim requires fenced completion")
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
            if connection.execute(
                "SELECT 1 FROM execution_claims WHERE key = ?",
                (key,),
            ).fetchone():
                connection.rollback()
                raise StaleFencingTokenError("active claim requires fenced completion")
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

    def claim_for_request(
        self,
        key: str,
        request_sha256: str,
        *,
        lease_seconds: float,
    ) -> ExecutionClaim:
        """Acquire one execution fence or return replay/busy/unknown without dispatch."""

        self._validate_claim_identity(key, request_sha256)
        now_ms, expires_at_ms = self._lease_expiry_ms(lease_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            terminal = connection.execute(
                "SELECT request_sha256, output_json FROM execution_ledger WHERE key = ?",
                (key,),
            ).fetchone()
            if terminal is not None:
                if terminal["request_sha256"] != request_sha256:
                    connection.rollback()
                    raise IdempotencyPayloadMismatchError
                output = self._decode(terminal["output_json"])
                connection.commit()
                return ExecutionClaim(ClaimDisposition.REPLAYED, output=output)

            claim = connection.execute(
                """
                SELECT request_sha256, fencing_token, lease_expires_at_ms, state,
                       retry_count, retry_limit
                FROM execution_claims
                WHERE key = ?
                """,
                (key,),
            ).fetchone()
            if claim is None:
                connection.execute(
                    """
                    INSERT INTO execution_claims (
                        key, request_sha256, fencing_token, lease_expires_at_ms, state,
                        retry_count, retry_limit
                    ) VALUES (?, ?, 1, ?, 'running', 0, ?)
                    """,
                    (key, request_sha256, expires_at_ms, self.max_retry_attempts),
                )
                connection.commit()
                return ExecutionClaim(
                    ClaimDisposition.ACQUIRED,
                    1,
                    expires_at_ms,
                    retry_count=0,
                    retry_limit=self.max_retry_attempts,
                )
            if claim["request_sha256"] != request_sha256:
                connection.rollback()
                raise IdempotencyPayloadMismatchError

            fencing_token = int(claim["fencing_token"])
            lease_expires_at_ms = int(claim["lease_expires_at_ms"])
            retry_count = int(claim["retry_count"])
            retry_limit = int(claim["retry_limit"])
            if claim["state"] == "unknown" or lease_expires_at_ms <= now_ms:
                if claim["state"] != "unknown":
                    connection.execute(
                        """
                        UPDATE execution_claims
                        SET state = 'unknown', updated_at = CURRENT_TIMESTAMP
                        WHERE key = ? AND fencing_token = ?
                        """,
                        (key, fencing_token),
                    )
                connection.commit()
                return ExecutionClaim(
                    ClaimDisposition.UNKNOWN,
                    fencing_token,
                    lease_expires_at_ms,
                    retry_count=retry_count,
                    retry_limit=retry_limit,
                )
            connection.commit()
            return ExecutionClaim(
                ClaimDisposition.BUSY,
                fencing_token,
                lease_expires_at_ms,
                retry_count=retry_count,
                retry_limit=retry_limit,
            )

    def _owned_running_claim(
        self,
        connection: sqlite3.Connection,
        key: str,
        request_sha256: str,
        fencing_token: int,
    ) -> sqlite3.Row:
        claim = connection.execute(
            """
            SELECT request_sha256, fencing_token, lease_expires_at_ms, state,
                   retry_count, retry_limit
            FROM execution_claims
            WHERE key = ?
            """,
            (key,),
        ).fetchone()
        if (
            claim is None
            or claim["request_sha256"] != request_sha256
            or claim["fencing_token"] != fencing_token
            or claim["state"] != "running"
        ):
            raise StaleFencingTokenError("claim ownership was lost")
        return claim

    def complete_claim(
        self,
        key: str,
        request_sha256: str,
        fencing_token: int,
        output: Payload,
    ) -> None:
        self._validate_claim_identity(key, request_sha256)
        self._validate_fencing_token(fencing_token)
        encoded = self._encode(output)
        now_ms = math.floor(self._clock() * 1_000)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            claim = self._owned_running_claim(
                connection,
                key,
                request_sha256,
                fencing_token,
            )
            if int(claim["lease_expires_at_ms"]) <= now_ms:
                connection.execute(
                    """
                    UPDATE execution_claims
                    SET state = 'unknown', updated_at = CURRENT_TIMESTAMP
                    WHERE key = ? AND fencing_token = ?
                    """,
                    (key, fencing_token),
                )
                connection.commit()
                raise StaleFencingTokenError("claim lease expired before completion")
            connection.execute(
                """
                INSERT INTO execution_ledger (key, request_sha256, output_json)
                VALUES (?, ?, ?)
                """,
                (key, request_sha256, encoded),
            )
            connection.execute(
                "DELETE FROM execution_claims WHERE key = ? AND fencing_token = ?",
                (key, fencing_token),
            )
            connection.commit()

    def abandon_claim(self, key: str, request_sha256: str, fencing_token: int) -> None:
        """Release a claim only when validation failed before the handler started."""

        self._validate_claim_identity(key, request_sha256)
        self._validate_fencing_token(fencing_token)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._owned_running_claim(connection, key, request_sha256, fencing_token)
            connection.execute(
                "DELETE FROM execution_claims WHERE key = ? AND fencing_token = ?",
                (key, fencing_token),
            )
            connection.commit()

    def mark_claim_unknown(self, key: str, request_sha256: str, fencing_token: int) -> None:
        """Block automatic retry when a dispatched handler has no trusted receipt."""

        self._validate_claim_identity(key, request_sha256)
        self._validate_fencing_token(fencing_token)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._owned_running_claim(connection, key, request_sha256, fencing_token)
            connection.execute(
                """
                UPDATE execution_claims
                SET state = 'unknown', updated_at = CURRENT_TIMESTAMP
                WHERE key = ? AND fencing_token = ?
                """,
                (key, fencing_token),
            )
            connection.commit()

    def retry_unknown_claim(
        self,
        key: str,
        request_sha256: str,
        expected_fencing_token: int,
        *,
        lease_seconds: float,
    ) -> ExecutionClaim:
        """Explicitly authorize a retry after reconciliation proved no side effect committed."""

        self._validate_claim_identity(key, request_sha256)
        self._validate_fencing_token(expected_fencing_token, may_increment=True)
        _now_ms, expires_at_ms = self._lease_expiry_ms(lease_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            claim = connection.execute(
                """
                SELECT request_sha256, fencing_token, state, retry_count, retry_limit
                FROM execution_claims
                WHERE key = ?
                """,
                (key,),
            ).fetchone()
            if (
                claim is None
                or claim["request_sha256"] != request_sha256
                or claim["fencing_token"] != expected_fencing_token
                or claim["state"] != "unknown"
            ):
                connection.rollback()
                raise StaleFencingTokenError("unknown claim changed before retry authorization")
            retry_count = int(claim["retry_count"])
            retry_limit = int(claim["retry_limit"])
            if retry_count >= retry_limit:
                connection.rollback()
                raise RetryBudgetExhaustedError(retry_count, retry_limit)
            next_token = expected_fencing_token + 1
            next_retry_count = retry_count + 1
            connection.execute(
                """
                UPDATE execution_claims
                SET fencing_token = ?, lease_expires_at_ms = ?, state = 'running',
                    retry_count = ?, updated_at = CURRENT_TIMESTAMP
                WHERE key = ?
                """,
                (next_token, expires_at_ms, next_retry_count, key),
            )
            connection.commit()
            return ExecutionClaim(
                ClaimDisposition.ACQUIRED,
                next_token,
                expires_at_ms,
                retry_count=next_retry_count,
                retry_limit=retry_limit,
            )

    def record_reconciled_success(
        self,
        key: str,
        request_sha256: str,
        expected_fencing_token: int,
        output: Payload,
    ) -> None:
        """Persist a trusted external receipt for an unknown outcome without redispatch."""

        self._validate_claim_identity(key, request_sha256)
        self._validate_fencing_token(expected_fencing_token)
        encoded = self._encode(output)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            claim = connection.execute(
                """
                SELECT request_sha256, fencing_token, state
                FROM execution_claims
                WHERE key = ?
                """,
                (key,),
            ).fetchone()
            if (
                claim is None
                or claim["request_sha256"] != request_sha256
                or claim["fencing_token"] != expected_fencing_token
                or claim["state"] != "unknown"
            ):
                connection.rollback()
                raise StaleFencingTokenError("unknown claim changed before reconciliation")
            connection.execute(
                """
                INSERT INTO execution_ledger (key, request_sha256, output_json)
                VALUES (?, ?, ?)
                """,
                (key, request_sha256, encoded),
            )
            connection.execute(
                "DELETE FROM execution_claims WHERE key = ? AND fencing_token = ?",
                (key, expected_fencing_token),
            )
            connection.commit()

    def record_authenticated_reconciled_success(
        self,
        receipt: ReconciliationReceipt,
        authenticator: ReceiptAuthenticator,
    ) -> None:
        """Consume one authentic receipt for the exact unknown claim without redispatch."""

        output = authenticator.verify(receipt)
        self.record_reconciled_success(
            receipt.key,
            receipt.request_sha256,
            receipt.fencing_token,
            output,
        )

    def retry_unknown_claim_authenticated(
        self,
        receipt: RetryAuthorizationReceipt,
        authenticator: ReceiptAuthenticator,
    ) -> ExecutionClaim:
        """Consume one authentic no-commit decision and advance the fence once."""
        retry_lease_ms = authenticator.verify_retry_authorization(receipt)
        return self.retry_unknown_claim(
            receipt.key,
            receipt.request_sha256,
            receipt.fencing_token,
            lease_seconds=retry_lease_ms / 1_000,
        )
