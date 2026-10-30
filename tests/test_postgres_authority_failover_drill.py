from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.postgres_authority_failover_drill import (
    FailoverDrillError,
    load_prepared_evidence,
    probe_old_primary_isolated,
    seal_evidence,
)


def prepared_payload() -> dict[str, object]:
    return {
        "checkpoint_sha256": "a" * 64,
        "generation": 1,
        "minimum_authority_epoch": 1,
        "phase": "prepared",
        "prepared_at_ms": 1_800_000_000_000,
        "primary_timeline": 1,
        "provider_id": "payments-postgres",
        "replica_synchronized": True,
        "schema": "authority_failover_drill",
        "schema_version": 1,
        "system_identifier_sha256": "b" * 64,
    }


def write(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")


def test_prepared_evidence_round_trip(tmp_path: Path) -> None:
    evidence = seal_evidence(prepared_payload())
    path = tmp_path / "prepared.json"
    write(path, evidence)

    assert load_prepared_evidence(path) == evidence


def test_prepared_evidence_rejects_tampering(tmp_path: Path) -> None:
    evidence = seal_evidence(prepared_payload())
    evidence["primary_timeline"] = 2
    path = tmp_path / "prepared.json"
    write(path, evidence)

    with pytest.raises(FailoverDrillError, match="digest_invalid"):
        load_prepared_evidence(path)


def test_prepared_evidence_rejects_duplicate_fields(tmp_path: Path) -> None:
    evidence = seal_evidence(prepared_payload())
    encoded = json.dumps(evidence, sort_keys=True)
    path = tmp_path / "prepared.json"
    path.write_text(encoded[:-1] + ',"phase":"prepared"}', encoding="utf-8")

    with pytest.raises(FailoverDrillError, match="duplicate_field"):
        load_prepared_evidence(path)


def test_prepared_evidence_rejects_sealed_unsafe_identifiers(tmp_path: Path) -> None:
    payload = prepared_payload()
    payload["schema"] = 'unsafe"schema'
    path = tmp_path / "prepared.json"
    write(path, seal_evidence(payload))

    with pytest.raises(FailoverDrillError, match="fields_invalid"):
        load_prepared_evidence(path)


class FakeOperationalError(Exception):
    def __init__(self, sqlstate: str | None = None) -> None:
        self.sqlstate = sqlstate


class FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakePsycopg:
    OperationalError = FakeOperationalError

    def __init__(self, result: object) -> None:
        self.result = result

    def connect(self, dsn: str, connect_timeout: int) -> FakeConnection:
        if isinstance(self.result, Exception):
            raise self.result
        assert isinstance(self.result, FakeConnection)
        return self.result


def test_old_primary_network_failure_proves_isolation() -> None:
    probe_old_primary_isolated("not-recorded", FakePsycopg(FakeOperationalError()))


def test_old_primary_auth_failure_is_inconclusive() -> None:
    with pytest.raises(FailoverDrillError, match="inconclusive"):
        probe_old_primary_isolated("not-recorded", FakePsycopg(FakeOperationalError("28P01")))


def test_reachable_old_primary_fails_drill_and_closes_probe() -> None:
    connection = FakeConnection()
    with pytest.raises(FailoverDrillError, match="still_reachable"):
        probe_old_primary_isolated("not-recorded", FakePsycopg(connection))
    assert connection.closed is True
