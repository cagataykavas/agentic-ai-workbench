from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping
from typing import Protocol, Self

from src.reconciliation_adapter import (
    DownstreamObservation,
    DownstreamOutcome,
    NegativeDurabilityProof,
    ReconciliationQuery,
    ReconciliationUnavailableError,
)

_IDENTIFIER_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_PROVIDER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_LSN_PATTERN = re.compile(r"[0-9A-F]+/[0-9A-F]+")
_MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807
_MAX_REPLICA_ACKNOWLEDGEMENTS = 32


class _Cursor(Protocol):
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
    except ImportError as exc:  # pragma: no cover - exercised by package smoke without the extra
        raise RuntimeError("install agentic-ai-workbench[postgres] for PostgreSQL support") from exc
    return psycopg.connect(
        dsn,
        connect_timeout=max(1, math.ceil(timeout_seconds)),
        application_name="agentic-ai-reconciler",
    )


def _quoted_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase PostgreSQL identifier")
    return f'"{value}"'


def _lsn_to_integer(value: object, name: str) -> int:
    if not isinstance(value, str) or _LSN_PATTERN.fullmatch(value) is None:
        raise ReconciliationUnavailableError(f"PostgreSQL {name} is malformed")
    high_text, low_text = value.split("/", 1)
    parsed = (int(high_text, 16) << 32) | int(low_text, 16)
    if parsed > _MAX_SQLITE_INTEGER:
        raise ReconciliationUnavailableError(f"PostgreSQL {name} exceeds the proof range")
    return parsed


class PostgresWalStatusProvider:
    """Read one claim and its protected WAL watermark from a primary snapshot.

    Writers must update the claim table and authority ``durable_sequence`` under the
    same serialization protocol. The authority row's ``minimum_wal_lsn`` is supplied
    by the failover controller; the provider refuses a primary that has not flushed
    through that watermark.
    """

    def __init__(
        self,
        *,
        provider_id: str,
        dsn: str,
        schema: str = "public",
        claim_table: str = "agent_reconciliation_claims",
        authority_table: str = "agent_reconciliation_authority",
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
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        quoted_schema = _quoted_identifier(schema, "schema")
        quoted_claim_table = _quoted_identifier(claim_table, "claim_table")
        quoted_authority_table = _quoted_identifier(authority_table, "authority_table")
        self.provider_id = provider_id
        self._dsn = dsn
        self._connection_factory = connection_factory
        self._query = self._build_query(
            f"{quoted_schema}.{quoted_claim_table}",
            f"{quoted_schema}.{quoted_authority_table}",
        )

    @staticmethod
    def _build_query(claim_table: str, authority_table: str) -> str:
        return f"""
WITH server_state AS (
    SELECT
        pg_is_in_recovery() AS in_recovery,
        CASE
            WHEN pg_is_in_recovery() THEN NULL
            ELSE pg_current_wal_flush_lsn()::text
        END AS flush_lsn,
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS observed_at_ms
),
authority AS (
    SELECT authority_epoch, durable_sequence, minimum_wal_lsn
    FROM {authority_table}
    WHERE singleton = TRUE
),
claim AS (
    SELECT request_sha256, fencing_token, status, output
    FROM {claim_table}
    WHERE idempotency_key = %s
)
SELECT
    server_state.in_recovery,
    server_state.flush_lsn,
    authority.authority_epoch,
    authority.durable_sequence,
    authority.minimum_wal_lsn::text,
    server_state.observed_at_ms,
    (
        SELECT count(*)::bigint
        FROM pg_stat_replication AS replica
        WHERE replica.sync_state IN ('sync', 'quorum')
          AND replica.replay_lsn >= authority.minimum_wal_lsn
    ) AS replica_acknowledgements,
    claim.request_sha256,
    claim.fencing_token,
    claim.status,
    claim.output
FROM server_state
CROSS JOIN authority
LEFT JOIN claim ON TRUE
""".strip()

    @staticmethod
    def _validate_timeout(timeout_seconds: float) -> int:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 30
        ):
            raise ValueError("timeout_seconds must be finite and in (0, 30]")
        return max(1, math.ceil(float(timeout_seconds) * 1_000))

    def _parse_row(
        self,
        row: tuple[object, ...],
        query: ReconciliationQuery,
    ) -> DownstreamObservation:
        if len(row) != 11:
            raise ReconciliationUnavailableError("PostgreSQL reconciliation row is malformed")
        (
            in_recovery,
            flush_lsn_text,
            authority_epoch,
            durable_sequence,
            minimum_wal_lsn_text,
            observed_at_ms,
            replica_acknowledgements,
            request_sha256,
            fencing_token,
            status,
            output,
        ) = row
        if in_recovery is not False:
            raise ReconciliationUnavailableError("PostgreSQL authority is not the primary")
        flush_lsn = _lsn_to_integer(flush_lsn_text, "flush LSN")
        minimum_wal_lsn = _lsn_to_integer(minimum_wal_lsn_text, "minimum WAL LSN")
        if flush_lsn < minimum_wal_lsn:
            raise ReconciliationUnavailableError("PostgreSQL WAL watermark has not been reached")
        if (
            type(authority_epoch) is not int
            or not 0 < authority_epoch <= _MAX_SQLITE_INTEGER
            or type(durable_sequence) is not int
            or not 0 <= durable_sequence <= _MAX_SQLITE_INTEGER
            or type(observed_at_ms) is not int
            or observed_at_ms < 0
            or type(replica_acknowledgements) is not int
            or not 0 <= replica_acknowledgements <= _MAX_REPLICA_ACKNOWLEDGEMENTS
        ):
            raise ReconciliationUnavailableError("PostgreSQL authority metadata is malformed")
        negative_proof = NegativeDurabilityProof(
            authority_epoch=authority_epoch,
            durable_sequence=durable_sequence,
            replica_acknowledgements=replica_acknowledgements,
        )
        claim_values = (request_sha256, fencing_token, status, output)
        if claim_values == (None, None, None, None):
            return DownstreamObservation(
                provider_id=self.provider_id,
                outcome=DownstreamOutcome.NOT_COMMITTED,
                key=query.key,
                request_sha256=query.request_sha256,
                fencing_token=query.fencing_token,
                observed_at_ms=observed_at_ms,
                negative_proof=negative_proof,
            )
        if request_sha256 != query.request_sha256 or fencing_token != query.fencing_token:
            raise ReconciliationUnavailableError("PostgreSQL claim identity mismatch")
        if status == DownstreamOutcome.PENDING.value and output is None:
            outcome = DownstreamOutcome.PENDING
            parsed_output = None
        elif status == DownstreamOutcome.COMMITTED.value:
            outcome = DownstreamOutcome.COMMITTED
            if isinstance(output, str):
                try:
                    output = json.loads(output)
                except json.JSONDecodeError as exc:
                    raise ReconciliationUnavailableError("PostgreSQL committed output is malformed") from exc
            if not isinstance(output, Mapping):
                raise ReconciliationUnavailableError("PostgreSQL committed output is malformed")
            parsed_output = dict(output)
        else:
            raise ReconciliationUnavailableError("PostgreSQL claim state is malformed")
        return DownstreamObservation(
            provider_id=self.provider_id,
            outcome=outcome,
            key=query.key,
            request_sha256=query.request_sha256,
            fencing_token=query.fencing_token,
            observed_at_ms=observed_at_ms,
            output=parsed_output,
        )

    def lookup(
        self,
        query: ReconciliationQuery,
        *,
        timeout_seconds: float,
    ) -> DownstreamObservation:
        if not isinstance(query, ReconciliationQuery):
            raise TypeError("query must be a ReconciliationQuery")
        timeout_milliseconds = self._validate_timeout(timeout_seconds)
        connection: _Connection | None = None
        try:
            connection = self._connection_factory(self._dsn, float(timeout_seconds))
            with connection.cursor() as cursor:
                cursor.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                timeout_setting = f"{timeout_milliseconds}ms"
                cursor.execute(
                    "SELECT set_config('statement_timeout', %s, TRUE)",
                    (timeout_setting,),
                )
                cursor.execute(
                    "SELECT set_config('idle_in_transaction_session_timeout', %s, TRUE)",
                    (timeout_setting,),
                )
                cursor.execute(self._query, (query.key,))
                rows = cursor.fetchall()
            if len(rows) != 1:
                raise ReconciliationUnavailableError("PostgreSQL authority snapshot is missing or ambiguous")
            observation = self._parse_row(rows[0], query)
            connection.commit()
            return observation
        except ReconciliationUnavailableError:
            raise
        except Exception as exc:
            raise ReconciliationUnavailableError("PostgreSQL lookup failed") from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except (OSError, RuntimeError):
                    pass
