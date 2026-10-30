from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.postgres_authority_failover_drill import (
    FailoverDrillError,
    audit_evidence_chain,
    load_prepared_evidence,
    load_verified_evidence,
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


def verified_payload(prepared: dict[str, object]) -> dict[str, object]:
    return {
        "checkpoint_sha256": "c" * 64,
        "generation": 2,
        "minimum_authority_epoch": 2,
        "new_timeline": 2,
        "old_primary_isolated": True,
        "phase": "verified",
        "pre_failover_checkpoint_sha256": prepared["checkpoint_sha256"],
        "pre_failover_timeline": prepared["primary_timeline"],
        "prepared_evidence_sha256": prepared["evidence_sha256"],
        "provider_id": prepared["provider_id"],
        "recovered_checkpoint": True,
        "schema_version": 1,
        "system_identifier_sha256": prepared["system_identifier_sha256"],
        "verified_at_ms": 1_800_000_001_000,
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


def test_archived_evidence_chain_audit_returns_digest_only_summary(tmp_path: Path) -> None:
    prepared = seal_evidence(prepared_payload())
    verified = seal_evidence(verified_payload(prepared))
    prepared_path = tmp_path / "prepared.json"
    verified_path = tmp_path / "verified.json"
    write(prepared_path, prepared)
    write(verified_path, verified)

    assert load_verified_evidence(verified_path) == verified
    assert audit_evidence_chain(prepared_path, verified_path) == {
        "audit": "passed",
        "authority_epoch_transition": [1, 2],
        "generation_transition": [1, 2],
        "prepared_evidence_sha256": prepared["evidence_sha256"],
        "provider_id": "payments-postgres",
        "schema_version": 1,
        "timeline_transition": [1, 2],
        "verified_evidence_sha256": verified["evidence_sha256"],
    }


def test_evidence_chain_rejects_valid_but_mismatched_preparation(tmp_path: Path) -> None:
    prepared = seal_evidence(prepared_payload())
    other_payload = prepared_payload()
    other_payload["checkpoint_sha256"] = "d" * 64
    other = seal_evidence(other_payload)
    verified = seal_evidence(verified_payload(prepared))
    prepared_path = tmp_path / "prepared.json"
    verified_path = tmp_path / "verified.json"
    write(prepared_path, other)
    write(verified_path, verified)

    with pytest.raises(FailoverDrillError, match="chain_binding_invalid"):
        audit_evidence_chain(prepared_path, verified_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("verified_at_ms", 1_799_999_999_999),
        ("checkpoint_sha256", "a" * 64),
    ],
)
def test_evidence_chain_rejects_impossible_transitions(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    prepared = seal_evidence(prepared_payload())
    verified_payload_document = verified_payload(prepared)
    verified_payload_document[field] = value
    verified = seal_evidence(verified_payload_document)
    prepared_path = tmp_path / "prepared.json"
    verified_path = tmp_path / "verified.json"
    write(prepared_path, prepared)
    write(verified_path, verified)

    with pytest.raises(FailoverDrillError, match="chain_transition_invalid"):
        audit_evidence_chain(prepared_path, verified_path)


def test_evidence_chain_rejects_non_advancing_timeline(tmp_path: Path) -> None:
    payload = prepared_payload()
    payload["primary_timeline"] = 2
    prepared = seal_evidence(payload)
    verified_payload_document = verified_payload(prepared)
    verified_payload_document["new_timeline"] = 2
    verified = seal_evidence(verified_payload_document)
    prepared_path = tmp_path / "prepared.json"
    verified_path = tmp_path / "verified.json"
    write(prepared_path, prepared)
    write(verified_path, verified)

    with pytest.raises(FailoverDrillError, match="chain_transition_invalid"):
        audit_evidence_chain(prepared_path, verified_path)


def test_verified_evidence_rejects_truthy_non_boolean_assertion(tmp_path: Path) -> None:
    prepared = seal_evidence(prepared_payload())
    payload = verified_payload(prepared)
    payload["old_primary_isolated"] = 1
    path = tmp_path / "verified.json"
    write(path, seal_evidence(payload))

    with pytest.raises(FailoverDrillError, match="verified_evidence_fields_invalid"):
        load_verified_evidence(path)


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
