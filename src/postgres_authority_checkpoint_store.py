from __future__ import annotations

import math
import re
from collections.abc import Callable
from typing import Protocol, Self

from src.authority_epoch_checkpoint import (
    dump_authority_epoch_checkpoint,
    load_authority_epoch_checkpoint,
)

_IDENTIFIER_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_PROVIDER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class AuthorityCheckpointStoreError(RuntimeError):
    """Base class for stable checkpoint-store failures."""


class AuthorityCheckpointStoreConflict(AuthorityCheckpointStoreError):
    """A compare-and-swap or monotonicity precondition failed."""


class AuthorityCheckpointStoreCorrupt(AuthorityCheckpointStoreError):
    """Persisted checkpoint state is malformed."""


class AuthorityCheckpointStoreUnavailable(AuthorityCheckpointStoreError):
    """PostgreSQL could not complete the checkpoint operation."""


class _Cursor(Protocol):
    rowcount: int

    def execute(self, query: str, params: object | None = None) -> object: ...

    def fetchall(self) -> list[tuple[object, ...]]: ...

    def __enter__(self) -> Self: ...

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...

    def commit(self) -> None: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[str, float], _Connection]


def _default_connection_factory(dsn: str, timeout_seconds: float) -> _Connection:
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - package smoke excludes the extra
        raise RuntimeError("install agentic-ai-workbench[postgres] for PostgreSQL support") from exc
    return psycopg.connect(
        dsn,
        connect_timeout=max(1, math.ceil(timeout_seconds)),
        application_name="agentic-ai-authority-checkpoint",
    )


def _quoted_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase PostgreSQL identifier")
    return f'"{value}"'


class PostgresAuthorityCheckpointStore:
    """Strongly consistent CAS storage for signed authority checkpoints.

    The table stores a canonical signed document and its digest in one row. Writers
    serialize on that row and must supply the previously observed digest. Database
    roles and the checkpoint signature remain separate authorization boundaries.
    """

    def __init__(
        self,
        *,
        provider_id: str,
        dsn: str,
        schema: str = "public",
        table: str = "agent_authority_epoch_checkpoints",
        timeout_seconds: float = 2.0,
        connection_factory: ConnectionFactory = _default_connection_factory,
    ) -> None:
        if not isinstance(provider_id, str) or _PROVIDER_ID_PATTERN.fullmatch(provider_id) is None:
            raise ValueError("provider_id must be 1-64 safe characters")
        if (
            not isinstance(dsn, str)
            or not dsn
            or len(dsn.encode("utf-8")) > 4_096
            or any(ord(character) < 32 for character in dsn)
        ):
            raise ValueError("dsn must be 1-4096 UTF-8 bytes without control characters")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 30
        ):
            raise ValueError("timeout_seconds must be finite and in (0, 30]")
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        self.provider_id = provider_id
        self._dsn = dsn
        self._timeout_seconds = float(timeout_seconds)
        self._connection_factory = connection_factory
        relation = f"{_quoted_identifier(schema, 'schema')}.{_quoted_identifier(table, 'table')}"
        self._relation = relation

    def initialize(self) -> None:
        """Create the checkpoint table inside an existing operator-owned schema."""

        statement = f"""
CREATE TABLE IF NOT EXISTS {self._relation} (
    provider_id text PRIMARY KEY,
    generation bigint NOT NULL CHECK (generation > 0),
    minimum_authority_epoch bigint NOT NULL CHECK (minimum_authority_epoch > 0),
    checkpoint_json text NOT NULL,
    checkpoint_sha256 char(64) NOT NULL CHECK (checkpoint_sha256 ~ '^[0-9a-f]{{64}}$')
)
""".strip()
        self._execute_write(lambda cursor: cursor.execute(statement))

    def load(self) -> tuple[str, str]:
        """Atomically load the checkpoint document and its anchored digest."""

        connection = self._connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                self._set_timeouts(cursor)
                cursor.execute(
                    f"SELECT checkpoint_json, checkpoint_sha256 FROM {self._relation} "
                    "WHERE provider_id = %s",
                    (self.provider_id,),
                )
                rows = cursor.fetchall()
                if len(rows) != 1:
                    raise AuthorityCheckpointStoreCorrupt("checkpoint_missing_or_ambiguous")
                document, digest = rows[0]
                checkpoint = self._validated_checkpoint(document, digest)
                connection.commit()
                return dump_authority_epoch_checkpoint(checkpoint), checkpoint.digest
        except AuthorityCheckpointStoreError:
            raise
        except Exception as exc:
            raise AuthorityCheckpointStoreUnavailable("checkpoint_store_unavailable") from exc
        finally:
            connection.close()

    def compare_and_swap(self, checkpoint_json: str, *, expected_sha256: str | None) -> str:
        """Install one monotonic checkpoint under an exact head-digest precondition."""

        if not isinstance(checkpoint_json, str) or len(checkpoint_json.encode("utf-8")) > 16_384:
            raise ValueError("checkpoint_json must be text no larger than 16384 UTF-8 bytes")
        checkpoint = load_authority_epoch_checkpoint(checkpoint_json)
        canonical = dump_authority_epoch_checkpoint(checkpoint)
        if checkpoint_json != canonical:
            raise ValueError("checkpoint_json must use canonical serialization")
        if checkpoint.provider_id != self.provider_id:
            raise ValueError("checkpoint provider_id does not match the store")
        if expected_sha256 is not None and _SHA256_PATTERN.fullmatch(expected_sha256) is None:
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")

        connection = self._connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                self._set_timeouts(cursor)
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (self.provider_id,),
                )
                cursor.execute(
                    f"SELECT generation, minimum_authority_epoch, checkpoint_json, "
                    f"checkpoint_sha256 FROM {self._relation} WHERE provider_id = %s FOR UPDATE",
                    (self.provider_id,),
                )
                rows = cursor.fetchall()
                if len(rows) > 1:
                    raise AuthorityCheckpointStoreCorrupt("checkpoint_ambiguous")
                current = rows[0] if rows else None
                current_digest = None if current is None else current[3]
                if current is not None:
                    current_checkpoint = self._validated_checkpoint(current[2], current_digest)
                    if (
                        current[0] != current_checkpoint.generation
                        or current[1] != current_checkpoint.minimum_authority_epoch
                    ):
                        raise AuthorityCheckpointStoreCorrupt("checkpoint_metadata_inconsistent")
                if current_digest != expected_sha256:
                    raise AuthorityCheckpointStoreConflict("checkpoint_head_mismatch")
                if current is not None:
                    if checkpoint.digest == current_digest:
                        connection.commit()
                        return checkpoint.digest
                    if checkpoint.generation <= current_checkpoint.generation:
                        raise AuthorityCheckpointStoreConflict("checkpoint_generation_not_monotonic")
                    if (
                        checkpoint.minimum_authority_epoch
                        < current_checkpoint.minimum_authority_epoch
                    ):
                        raise AuthorityCheckpointStoreConflict("checkpoint_epoch_regressed")
                    cursor.execute(
                        f"UPDATE {self._relation} SET generation = %s, "
                        "minimum_authority_epoch = %s, checkpoint_json = %s, checkpoint_sha256 = %s "
                        "WHERE provider_id = %s AND checkpoint_sha256 = %s",
                        (
                            checkpoint.generation,
                            checkpoint.minimum_authority_epoch,
                            canonical,
                            checkpoint.digest,
                            self.provider_id,
                            expected_sha256,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise AuthorityCheckpointStoreConflict("checkpoint_head_mismatch")
                else:
                    cursor.execute(
                        f"INSERT INTO {self._relation} "
                        "(provider_id, generation, minimum_authority_epoch, checkpoint_json, "
                        "checkpoint_sha256) VALUES (%s, %s, %s, %s, %s)",
                        (
                            self.provider_id,
                            checkpoint.generation,
                            checkpoint.minimum_authority_epoch,
                            canonical,
                            checkpoint.digest,
                        ),
                    )
                connection.commit()
                return checkpoint.digest
        except AuthorityCheckpointStoreError:
            raise
        except Exception as exc:
            raise AuthorityCheckpointStoreUnavailable("checkpoint_store_unavailable") from exc
        finally:
            connection.close()

    def _connect(self) -> _Connection:
        try:
            return self._connection_factory(self._dsn, self._timeout_seconds)
        except Exception as exc:
            raise AuthorityCheckpointStoreUnavailable("checkpoint_store_unavailable") from exc

    def _execute_write(self, operation: Callable[[_Cursor], object]) -> None:
        connection = self._connect()
        try:
            with connection.cursor() as cursor:
                self._set_timeouts(cursor)
                operation(cursor)
            connection.commit()
        except AuthorityCheckpointStoreError:
            raise
        except Exception as exc:
            raise AuthorityCheckpointStoreUnavailable("checkpoint_store_unavailable") from exc
        finally:
            connection.close()

    def _set_timeouts(self, cursor: _Cursor) -> None:
        timeout_ms = max(1, math.ceil(self._timeout_seconds * 1_000))
        cursor.execute("SELECT set_config('statement_timeout', %s, TRUE)", (f"{timeout_ms}ms",))
        cursor.execute(
            "SELECT set_config('idle_in_transaction_session_timeout', %s, TRUE)",
            (f"{timeout_ms}ms",),
        )

    def _validated_checkpoint(self, document: object, digest: object):
        if not isinstance(document, str) or not isinstance(digest, str):
            raise AuthorityCheckpointStoreCorrupt("checkpoint_row_malformed")
        if len(document.encode("utf-8")) > 16_384 or _SHA256_PATTERN.fullmatch(digest) is None:
            raise AuthorityCheckpointStoreCorrupt("checkpoint_row_malformed")
        try:
            checkpoint = load_authority_epoch_checkpoint(document)
        except Exception as exc:
            raise AuthorityCheckpointStoreCorrupt("checkpoint_document_invalid") from exc
        if dump_authority_epoch_checkpoint(checkpoint) != document:
            raise AuthorityCheckpointStoreCorrupt("checkpoint_document_noncanonical")
        if checkpoint.provider_id != self.provider_id or checkpoint.digest != digest:
            raise AuthorityCheckpointStoreCorrupt("checkpoint_row_inconsistent")
        return checkpoint
