from __future__ import annotations

import os
import uuid

import pytest

from src.authority_epoch_checkpoint import (
    SignedAuthorityEpochSource,
    dump_authority_epoch_checkpoint,
    sign_authority_epoch_checkpoint,
)
from src.postgres_authority_checkpoint_store import (
    AuthorityCheckpointStoreConflict,
    AuthorityCheckpointStoreCorrupt,
    AuthorityCheckpointStoreUnavailable,
    PostgresAuthorityCheckpointStore,
)

SECRET = b"postgres-checkpoint-store-test-key"
NOW_MS = 1_800_000_000_000


def checkpoint(*, generation: int, minimum_epoch: int, provider_id: str = "payments-postgres"):
    return sign_authority_epoch_checkpoint(
        provider_id=provider_id,
        generation=generation,
        minimum_authority_epoch=minimum_epoch,
        issued_at_ms=NOW_MS,
        key_id="current",
        secret=SECRET,
    )


def disconnected_store(**changes: object) -> PostgresAuthorityCheckpointStore:
    def fail_if_called(dsn: str, timeout_seconds: float):
        raise AssertionError(f"unexpected connection: {dsn} {timeout_seconds}")

    values: dict[str, object] = {
        "provider_id": "payments-postgres",
        "dsn": "postgresql://authority.invalid/control",
        "connection_factory": fail_if_called,
    }
    values.update(changes)
    return PostgresAuthorityCheckpointStore(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"provider_id": "unsafe provider"}, "provider_id"),
        ({"schema": "Public"}, "schema"),
        ({"table": "checkpoints;drop"}, "table"),
        ({"dsn": "postgresql://host/db\npassword=secret"}, "dsn"),
        ({"timeout_seconds": 0}, "timeout_seconds"),
    ],
)
def test_constructor_rejects_unsafe_configuration(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        disconnected_store(**changes)


def test_compare_and_swap_validates_document_before_database_access() -> None:
    store = disconnected_store()
    valid = checkpoint(generation=1, minimum_epoch=1)
    canonical = dump_authority_epoch_checkpoint(valid)

    with pytest.raises(ValueError, match="canonical"):
        store.compare_and_swap(f" {canonical}", expected_sha256=None)
    wrong_provider = checkpoint(
        generation=1,
        minimum_epoch=1,
        provider_id="other-postgres",
    )
    with pytest.raises(ValueError, match="provider_id"):
        store.compare_and_swap(
            dump_authority_epoch_checkpoint(wrong_provider),
            expected_sha256=None,
        )
    with pytest.raises(ValueError, match="expected_sha256"):
        store.compare_and_swap(canonical, expected_sha256="bad")


def test_connection_failure_is_normalized_without_dsn_or_diagnostic() -> None:
    def failing_factory(dsn: str, timeout_seconds: float):
        raise RuntimeError(f"secret database diagnostic from {dsn}")

    store = PostgresAuthorityCheckpointStore(
        provider_id="payments-postgres",
        dsn="postgresql://user:secret@authority.invalid/control",
        connection_factory=failing_factory,
    )

    with pytest.raises(AuthorityCheckpointStoreUnavailable) as caught:
        store.load()
    assert "secret" not in str(caught.value)
    assert "authority.invalid" not in str(caught.value)


@pytest.mark.skipif(
    "AGENTIC_TEST_POSTGRES_DSN" not in os.environ,
    reason="set AGENTIC_TEST_POSTGRES_DSN to run the live PostgreSQL contract",
)
def test_live_postgres_checkpoint_cas_and_epoch_source_contract() -> None:
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["AGENTIC_TEST_POSTGRES_DSN"]
    schema = f"agent_checkpoint_{uuid.uuid4().hex}"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(f'CREATE SCHEMA "{schema}"')
    try:
        store = PostgresAuthorityCheckpointStore(
            provider_id="payments-postgres",
            dsn=dsn,
            schema=schema,
        )
        store.initialize()
        first = checkpoint(generation=1, minimum_epoch=1)
        first_json = dump_authority_epoch_checkpoint(first)

        assert store.compare_and_swap(first_json, expected_sha256=None) == first.digest
        assert store.load() == (first_json, first.digest)
        assert store.compare_and_swap(first_json, expected_sha256=first.digest) == first.digest

        source = SignedAuthorityEpochSource(
            provider_id="payments-postgres",
            checkpoint_loader=store.load,
            keyring={"current": SECRET},
            clock=lambda: NOW_MS / 1_000,
        )
        assert source.current_requirement().minimum_authority_epoch == 1

        second = checkpoint(generation=2, minimum_epoch=2)
        second_json = dump_authority_epoch_checkpoint(second)
        assert store.compare_and_swap(second_json, expected_sha256=first.digest) == second.digest
        assert source.current_requirement().minimum_authority_epoch == 2

        third = checkpoint(generation=3, minimum_epoch=3)
        with pytest.raises(AuthorityCheckpointStoreConflict, match="head_mismatch"):
            store.compare_and_swap(
                dump_authority_epoch_checkpoint(third),
                expected_sha256=first.digest,
            )
        regressed = checkpoint(generation=3, minimum_epoch=1)
        with pytest.raises(AuthorityCheckpointStoreConflict, match="epoch_regressed"):
            store.compare_and_swap(
                dump_authority_epoch_checkpoint(regressed),
                expected_sha256=second.digest,
            )

        with psycopg.connect(dsn) as connection:
            connection.execute(
                f'UPDATE "{schema}".agent_authority_epoch_checkpoints '
                "SET generation = 99 WHERE provider_id = %s",
                ("payments-postgres",),
            )
        with pytest.raises(AuthorityCheckpointStoreCorrupt, match="metadata_inconsistent"):
            store.compare_and_swap(
                dump_authority_epoch_checkpoint(third),
                expected_sha256=second.digest,
            )
        with psycopg.connect(dsn) as connection:
            connection.execute(
                f'UPDATE "{schema}".agent_authority_epoch_checkpoints '
                "SET generation = 2, checkpoint_json = '{}' WHERE provider_id = %s",
                ("payments-postgres",),
            )
        with pytest.raises(AuthorityCheckpointStoreCorrupt, match="document_invalid"):
            store.load()
    finally:
        with psycopg.connect(dsn, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA "{schema}" CASCADE')
