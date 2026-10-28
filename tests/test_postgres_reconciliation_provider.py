from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Self

import pytest

from src.postgres_reconciliation_provider import PostgresWalStatusProvider
from src.reconciliation import ReceiptAuthenticator, RetryAuthorizationReceipt
from src.reconciliation_adapter import (
    AuthoritativeReconciliationCoordinator,
    DownstreamOutcome,
    NegativeObservationPolicy,
    ReconciliationQuery,
    ReconciliationUnavailableError,
)

KEY = "payment:request-7"
REQUEST_SHA256 = "a" * 64
QUERY = ReconciliationQuery(KEY, REQUEST_SHA256, 1)


def row(
    *,
    in_recovery: object = False,
    flush_lsn: object = "0/200",
    authority_epoch: object = 7,
    durable_sequence: object = 41,
    minimum_wal_lsn: object = "0/100",
    observed_at_ms: object = 100_000,
    replica_acknowledgements: object = 1,
    request_sha256: object = None,
    fencing_token: object = None,
    status: object = None,
    output: object = None,
) -> tuple[object, ...]:
    return (
        in_recovery,
        flush_lsn,
        authority_epoch,
        durable_sequence,
        minimum_wal_lsn,
        observed_at_ms,
        replica_acknowledgements,
        request_sha256,
        fencing_token,
        status,
        output,
    )


@dataclass
class FakeCursor:
    rows: list[tuple[object, ...]]
    executions: list[tuple[str, object | None]] = field(default_factory=list)

    def execute(self, query: str, params: object | None = None) -> None:
        self.executions.append((query, params))

    def fetchall(self) -> list[tuple[object, ...]]:
        return self.rows

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None


@dataclass
class FakeConnection:
    rows: list[tuple[object, ...]]
    cursor_instance: FakeCursor = field(init=False)
    commits: int = 0
    closed: bool = False

    def __post_init__(self) -> None:
        self.cursor_instance = FakeCursor(self.rows)

    def cursor(self) -> FakeCursor:
        return self.cursor_instance

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        self.closed = True


def provider_for(
    rows: list[tuple[object, ...]],
) -> tuple[PostgresWalStatusProvider, FakeConnection, list[tuple[str, float]]]:
    connection = FakeConnection(rows)
    calls: list[tuple[str, float]] = []

    def factory(dsn: str, timeout_seconds: float) -> FakeConnection:
        calls.append((dsn, timeout_seconds))
        return connection

    provider = PostgresWalStatusProvider(
        provider_id="payments-postgres",
        dsn="postgresql://authority.invalid/reconciliation",
        schema="agent_runtime",
        connection_factory=factory,
    )
    return provider, connection, calls


def test_absent_claim_derives_negative_proof_from_primary_wal_snapshot() -> None:
    provider, connection, calls = provider_for([row()])

    observation = provider.lookup(QUERY, timeout_seconds=0.25)

    assert observation.outcome is DownstreamOutcome.NOT_COMMITTED
    assert observation.negative_proof is not None
    assert observation.negative_proof.authority_epoch == 7
    assert observation.negative_proof.durable_sequence == 41
    assert observation.negative_proof.replica_acknowledgements == 1
    assert calls == [("postgresql://authority.invalid/reconciliation", 0.25)]
    assert connection.commits == 1
    assert connection.closed
    statements = connection.cursor_instance.executions
    assert statements[0][0] == "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    assert statements[1] == (
        "SELECT set_config('statement_timeout', %s, TRUE)",
        ("250ms",),
    )
    assert statements[2] == (
        "SELECT set_config('idle_in_transaction_session_timeout', %s, TRUE)",
        ("250ms",),
    )
    assert statements[3][1] == (KEY,)
    assert '"agent_runtime"."agent_reconciliation_claims"' in statements[3][0]
    assert KEY not in statements[3][0]


def test_wal_proof_can_authorize_only_the_configured_negative_watermark() -> None:
    provider, _, _ = provider_for([row()])
    authenticator = ReceiptAuthenticator(
        {"current": b"a" * 32},
        signing_key_id="current",
        clock=lambda: 100.0,
    )
    coordinator = AuthoritativeReconciliationCoordinator(
        provider,
        authenticator,
        negative_observation_policy=NegativeObservationPolicy(
            minimum_authority_epoch=7,
            minimum_durable_sequence=41,
        ),
        clock=lambda: 100.0,
        monotonic=lambda: 1.0,
    )

    decision = coordinator.reconcile(QUERY, retry_lease_seconds=3)

    assert isinstance(decision.receipt, RetryAuthorizationReceipt)
    assert authenticator.verify_retry_authorization(decision.receipt) == 3_000


@pytest.mark.parametrize(
    ("database_row", "outcome", "expected_output"),
    [
        (
            row(
                request_sha256=REQUEST_SHA256,
                fencing_token=1,
                status="committed",
                output={"payment_id": "p-7"},
            ),
            DownstreamOutcome.COMMITTED,
            {"payment_id": "p-7"},
        ),
        (
            row(
                request_sha256=REQUEST_SHA256,
                fencing_token=1,
                status="committed",
                output='{"payment_id":"p-7"}',
            ),
            DownstreamOutcome.COMMITTED,
            {"payment_id": "p-7"},
        ),
        (
            row(
                request_sha256=REQUEST_SHA256,
                fencing_token=1,
                status="pending",
            ),
            DownstreamOutcome.PENDING,
            None,
        ),
    ],
)
def test_existing_claim_maps_strict_state(
    database_row: tuple[object, ...],
    outcome: DownstreamOutcome,
    expected_output: dict[str, object] | None,
) -> None:
    provider, _, _ = provider_for([database_row])

    observation = provider.lookup(QUERY, timeout_seconds=1)

    assert observation.outcome is outcome
    assert observation.output == expected_output
    assert observation.negative_proof is None


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([row(in_recovery=True, flush_lsn=None)], "not the primary"),
        ([row(flush_lsn="0/FF", minimum_wal_lsn="0/100")], "watermark"),
        ([row(flush_lsn="not-an-lsn")], "flush LSN"),
        ([row(authority_epoch=True)], "authority metadata"),
        ([row(replica_acknowledgements=33)], "authority metadata"),
        ([], "missing or ambiguous"),
        ([row(), row()], "missing or ambiguous"),
        (
            [
                row(
                    request_sha256="b" * 64,
                    fencing_token=1,
                    status="pending",
                )
            ],
            "claim identity",
        ),
        (
            [
                row(
                    request_sha256=REQUEST_SHA256,
                    fencing_token=1,
                    status="committed",
                    output=None,
                )
            ],
            "committed output",
        ),
    ],
)
def test_unsafe_or_ambiguous_database_state_fails_closed(
    rows: list[tuple[object, ...]],
    message: str,
) -> None:
    provider, connection, _ = provider_for(rows)

    with pytest.raises(ReconciliationUnavailableError, match=message):
        provider.lookup(QUERY, timeout_seconds=1)

    assert connection.commits == 0
    assert connection.closed


def test_database_failure_is_normalized_without_dsn_or_diagnostic() -> None:
    def failing_factory(dsn: str, timeout_seconds: float) -> FakeConnection:
        raise RuntimeError(f"secret diagnostic from {dsn}")

    provider = PostgresWalStatusProvider(
        provider_id="payments-postgres",
        dsn="postgresql://user:secret@authority.invalid/reconciliation",
        connection_factory=failing_factory,
    )

    with pytest.raises(ReconciliationUnavailableError, match="PostgreSQL lookup failed") as caught:
        provider.lookup(QUERY, timeout_seconds=1)

    assert "secret" not in str(caught.value)
    assert "authority.invalid" not in str(caught.value)


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"schema": "public; DROP SCHEMA public"}, "schema"),
        ({"claim_table": "Claims"}, "claim_table"),
        ({"authority_table": "authority-table"}, "authority_table"),
        ({"dsn": "postgresql://host/db\npassword=secret"}, "dsn"),
    ],
)
def test_constructor_rejects_identifier_injection_and_unsafe_dsn(
    arguments: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "provider_id": "payments-postgres",
        "dsn": "postgresql://authority.invalid/reconciliation",
        "connection_factory": lambda dsn, timeout: FakeConnection([row()]),
    }
    values.update(arguments)

    with pytest.raises(ValueError, match=message):
        PostgresWalStatusProvider(**values)  # type: ignore[arg-type]


def test_timeout_is_bounded_and_rounded_up_to_one_millisecond() -> None:
    provider, connection, _ = provider_for([row()])

    provider.lookup(QUERY, timeout_seconds=0.0001)

    assert connection.cursor_instance.executions[1][1] == ("1ms",)
    with pytest.raises(ValueError, match="timeout_seconds"):
        provider.lookup(QUERY, timeout_seconds=True)


@pytest.mark.skipif(
    "AGENTIC_TEST_POSTGRES_DSN" not in os.environ,
    reason="set AGENTIC_TEST_POSTGRES_DSN to run the live PostgreSQL contract",
)
def test_live_postgres_primary_snapshot_and_committed_claim() -> None:
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["AGENTIC_TEST_POSTGRES_DSN"]
    schema = f"agent_test_{uuid.uuid4().hex}"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(f'CREATE SCHEMA "{schema}"')
        connection.execute(
            f"""
            CREATE TABLE "{schema}".agent_reconciliation_authority (
                singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
                authority_epoch bigint NOT NULL CHECK (authority_epoch > 0),
                durable_sequence bigint NOT NULL CHECK (durable_sequence >= 0),
                minimum_wal_lsn pg_lsn NOT NULL
            )
            """
        )
        connection.execute(
            f"""
            CREATE TABLE "{schema}".agent_reconciliation_claims (
                idempotency_key text PRIMARY KEY,
                request_sha256 text NOT NULL,
                fencing_token bigint NOT NULL,
                status text NOT NULL CHECK (status IN ('pending', 'committed')),
                output jsonb
            )
            """
        )
        connection.execute(
            f"""
            INSERT INTO "{schema}".agent_reconciliation_authority
                (singleton, authority_epoch, durable_sequence, minimum_wal_lsn)
            VALUES (TRUE, 7, 41, pg_current_wal_flush_lsn())
            """
        )
    try:
        provider = PostgresWalStatusProvider(
            provider_id="payments-postgres",
            dsn=dsn,
            schema=schema,
        )

        absent = provider.lookup(QUERY, timeout_seconds=2)

        assert absent.outcome is DownstreamOutcome.NOT_COMMITTED
        assert absent.negative_proof is not None
        assert absent.negative_proof.authority_epoch == 7
        assert absent.negative_proof.durable_sequence == 41

        with psycopg.connect(dsn) as connection:
            connection.execute(
                f"""
                INSERT INTO "{schema}".agent_reconciliation_claims
                    (idempotency_key, request_sha256, fencing_token, status, output)
                VALUES (%s, %s, %s, 'committed', %s::jsonb)
                """,
                (KEY, REQUEST_SHA256, 1, json.dumps({"payment_id": "p-7"})),
            )
            connection.execute(
                f'UPDATE "{schema}".agent_reconciliation_authority '
                "SET durable_sequence = 42, minimum_wal_lsn = pg_current_wal_flush_lsn()"
            )

        committed = provider.lookup(QUERY, timeout_seconds=2)

        assert committed.outcome is DownstreamOutcome.COMMITTED
        assert committed.output == {"payment_id": "p-7"}
        assert committed.negative_proof is None
    finally:
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA "{schema}" CASCADE')
