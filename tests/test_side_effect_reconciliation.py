from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.side_effect_reconciliation import (
    ArtifactMalformed,
    ReconciliationPolicy,
    audit_artifact,
    load_artifact,
)

AS_OF = datetime(2026, 9, 26, 20, 0, tzinfo=UTC)
INTENT = "a" * 64
KEY = "b" * 64
OPERATION = "c" * 64
COMPENSATION = "d" * 64


def receipt(
    *,
    receipt_id: str = "receipt-1",
    operation: str = OPERATION,
    status: str = "committed",
    observed_at: str = "2026-09-26T19:20:00Z",
    compensates: str | None = None,
) -> dict:
    return {
        "receipt_id": receipt_id,
        "operation_sha256": operation,
        "intent_sha256": INTENT,
        "idempotency_key_sha256": KEY,
        "status": status,
        "observed_at": observed_at,
        "compensates_operation_sha256": compensates,
    }


def call(
    *,
    call_id: str = "call-1",
    effect_kind: str = "idempotent",
    runtime_state: str = "succeeded",
    finished_at: str | None = "2026-09-26T19:21:00Z",
    lease_expires_at: str = "2026-09-26T19:10:00Z",
    receipts: list[dict] | None = None,
) -> dict:
    return {
        "call_id": call_id,
        "tool": "crm.update",
        "intent_sha256": INTENT,
        "idempotency_key_sha256": None if effect_kind == "none" else KEY,
        "effect_kind": effect_kind,
        "runtime_state": runtime_state,
        "started_at": "2026-09-26T19:00:00Z",
        "finished_at": finished_at,
        "lease_expires_at": lease_expires_at,
        "receipts": [receipt()] if receipts is None else receipts,
    }


def artifact(calls: list[dict] | None = None) -> dict:
    return {
        "schema_version": 1,
        "run_id": "run-17",
        "policy_id": "prod-v3",
        "observed_at": "2026-09-26T19:30:00Z",
        "calls": [call()] if calls is None else calls,
    }


def codes(report) -> set[str]:
    return {finding.code for finding in report.findings}


def test_clean_succeeded_write_is_accepted() -> None:
    report = audit_artifact(artifact(), as_of=AS_OF)
    assert report.accepted is True
    assert report.status == "clean"
    assert report.call_count == 1
    assert report.receipt_count == 1


def test_failed_idempotent_write_with_commit_is_marked_succeeded() -> None:
    item = call(runtime_state="failed")
    report = audit_artifact(artifact([item]), as_of=AS_OF)
    assert codes(report) == {"COMMITTED_EFFECT_NOT_ACKNOWLEDGED"}
    assert report.findings[0].action == "mark_succeeded"


def test_failed_write_without_receipt_is_not_treated_as_clean() -> None:
    idempotent = call(runtime_state="failed", receipts=[])
    report = audit_artifact(artifact([idempotent]), as_of=AS_OF)
    assert codes(report) == {"FAILED_WRITE_WITHOUT_RECEIPT"}
    assert report.findings[0].action == "retry_same_key"

    irreversible = call(effect_kind="irreversible", runtime_state="failed", receipts=[])
    report = audit_artifact(artifact([irreversible]), as_of=AS_OF)
    assert report.findings[0].action == "query_then_escalate"


def test_authoritative_rejection_makes_failed_write_clean() -> None:
    rejected = receipt(status="rejected")
    item = call(runtime_state="failed", receipts=[rejected])
    assert audit_artifact(artifact([item]), as_of=AS_OF).accepted is True


def test_unacknowledged_rejection_marks_unknown_call_failed() -> None:
    rejected = receipt(status="rejected")
    item = call(runtime_state="unknown", finished_at=None, receipts=[rejected])
    report = audit_artifact(artifact([item]), as_of=AS_OF)
    assert codes(report) == {"REJECTED_EFFECT_NOT_ACKNOWLEDGED"}
    assert report.findings[0].action == "mark_failed"


def test_stranded_idempotent_write_without_receipt_reuses_same_key() -> None:
    item = call(runtime_state="executing", finished_at=None, receipts=[])
    report = audit_artifact(artifact([item]), as_of=AS_OF)
    assert codes(report) == {"STRANDED_IDEMPOTENT_WRITE"}
    assert report.findings[0].action == "retry_same_key"


def test_live_execution_waits_instead_of_recommending_retry() -> None:
    item = call(
        runtime_state="executing",
        finished_at=None,
        lease_expires_at="2026-09-26T19:45:00Z",
        receipts=[],
    )
    report = audit_artifact(artifact([item]), as_of=AS_OF)
    assert codes(report) == {"CALL_STILL_IN_FLIGHT"}
    assert report.findings[0].action == "wait"


def test_compensatable_failure_requests_compensation() -> None:
    item = call(effect_kind="compensatable", runtime_state="failed")
    report = audit_artifact(artifact([item]), as_of=AS_OF)
    assert codes(report) == {"UNCOMPENSATED_PARTIAL_EFFECT"}
    assert report.findings[0].action == "compensate"


def test_completed_compensation_clears_failed_call() -> None:
    receipts = [
        receipt(),
        receipt(
            receipt_id="receipt-2",
            operation=COMPENSATION,
            status="compensated",
            observed_at="2026-09-26T19:22:00Z",
            compensates=OPERATION,
        ),
    ]
    item = call(effect_kind="compensatable", runtime_state="failed", receipts=receipts)
    report = audit_artifact(artifact([item]), as_of=AS_OF)
    assert report.accepted is True
    assert report.receipt_count == 2


def test_irreversible_effect_after_failure_requires_escalation() -> None:
    item = call(effect_kind="irreversible", runtime_state="failed")
    report = audit_artifact(artifact([item]), as_of=AS_OF)
    assert codes(report) == {"IRREVERSIBLE_EFFECT_AFTER_FAILURE"}
    assert report.findings[0].action == "escalate"


def test_duplicate_remote_operations_are_rejected() -> None:
    receipts = [receipt(), receipt(receipt_id="receipt-2", operation="e" * 64)]
    report = audit_artifact(artifact([call(receipts=receipts)]), as_of=AS_OF)
    assert "DUPLICATE_REMOTE_EFFECT" in codes(report)


def test_read_only_call_with_commit_is_rejected() -> None:
    item = call(effect_kind="none")
    item["receipts"][0]["idempotency_key_sha256"] = None
    report = audit_artifact(artifact([item]), as_of=AS_OF)
    assert codes(report) == {"READ_ONLY_CALL_HAS_REMOTE_COMMIT"}


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda value: value["calls"][0].update(intent_sha256="BAD"), "INTENT_SHA256"),
        (
            lambda value: value["calls"][0]["receipts"][0].update(intent_sha256="f" * 64),
            "RECEIPT_BINDING_MISMATCH",
        ),
        (
            lambda value: value["calls"][0].update(idempotency_key_sha256=None),
            "WRITE_WITHOUT_IDEMPOTENCY_KEY",
        ),
        (
            lambda value: value["calls"][0].update(finished_at=None),
            "TERMINAL_STATE_WITHOUT_FINISH",
        ),
    ],
)
def test_malformed_artifact_fails_closed(mutation, expected: str) -> None:
    value = artifact()
    mutation(value)
    with pytest.raises(ArtifactMalformed, match=expected):
        audit_artifact(value, as_of=AS_OF)


def test_orphan_compensation_fails_closed() -> None:
    compensation = receipt(
        operation=COMPENSATION,
        status="compensated",
        compensates="e" * 64,
    )
    with pytest.raises(ArtifactMalformed, match="ORPHAN_COMPENSATION"):
        audit_artifact(
            artifact([call(effect_kind="compensatable", runtime_state="failed", receipts=[compensation])]),
            as_of=AS_OF,
        )


def test_duplicate_json_keys_and_non_finite_values_are_rejected() -> None:
    policy = ReconciliationPolicy()
    with pytest.raises(ArtifactMalformed, match="DUPLICATE_JSON_KEY"):
        load_artifact(b'{"schema_version":1,"schema_version":1}', policy)
    with pytest.raises(ArtifactMalformed, match="NON_FINITE_NUMBER"):
        load_artifact(b'{"value":NaN}', policy)


def test_input_call_and_receipt_budgets_are_enforced() -> None:
    with pytest.raises(ArtifactMalformed, match="INPUT_TOO_LARGE"):
        load_artifact(b"{} ", ReconciliationPolicy(max_input_bytes=2))
    value = artifact([call(call_id="one"), call(call_id="two")])
    with pytest.raises(ArtifactMalformed, match="CALL_BUDGET_EXCEEDED"):
        audit_artifact(value, as_of=AS_OF, policy=ReconciliationPolicy(max_calls=1))
    value = artifact([call(receipts=[receipt(), receipt(receipt_id="two", operation="e" * 64)])])
    with pytest.raises(ArtifactMalformed, match="RECEIPT_BUDGET_EXCEEDED"):
        audit_artifact(
            value,
            as_of=AS_OF,
            policy=ReconciliationPolicy(max_receipts_per_call=1),
        )


def test_stale_and_future_evidence_are_rejected() -> None:
    stale = artifact()
    stale["observed_at"] = "2026-09-20T19:30:00Z"
    with pytest.raises(ArtifactMalformed, match="STALE_EVIDENCE"):
        audit_artifact(stale, as_of=AS_OF)
    future = artifact()
    future["observed_at"] = "2026-09-26T20:02:00Z"
    with pytest.raises(ArtifactMalformed, match="EVIDENCE_FROM_FUTURE"):
        audit_artifact(future, as_of=AS_OF)


def test_report_is_order_independent_and_does_not_expose_identifiers() -> None:
    first = call(call_id="customer-write", runtime_state="failed")
    second = call(call_id="invoice-write", runtime_state="failed")
    second["receipts"][0]["receipt_id"] = "receipt-2"
    second["receipts"][0]["operation_sha256"] = "e" * 64
    report_a = audit_artifact(artifact([first, second]), as_of=AS_OF)
    report_b = audit_artifact(artifact([second, first]), as_of=AS_OF)
    assert report_a.artifact_sha256 != report_b.artifact_sha256
    assert report_a.findings == report_b.findings
    serialized = json.dumps(report_a.to_dict())
    assert "customer-write" not in serialized
    assert "invoice-write" not in serialized
    assert "crm.update" not in serialized


def test_artifact_digest_is_canonical_across_json_layout() -> None:
    value = artifact()
    raw_a = json.dumps(value, indent=2).encode()
    raw_b = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    report_a = audit_artifact(load_artifact(raw_a, ReconciliationPolicy()), as_of=AS_OF)
    report_b = audit_artifact(load_artifact(raw_b, ReconciliationPolicy()), as_of=AS_OF)
    assert report_a.artifact_sha256 == report_b.artifact_sha256


def test_cli_uses_distinct_clean_policy_and_malformed_exit_codes(tmp_path: Path) -> None:
    artifact_path = tmp_path / "artifact.json"
    output_path = tmp_path / "report.json"
    artifact_path.write_text(json.dumps(artifact()), encoding="utf-8")
    command = [
        sys.executable,
        "-m",
        "src.side_effect_reconciliation",
        str(artifact_path),
        "--as-of",
        "2026-09-26T20:00:00Z",
        "--output",
        str(output_path),
    ]
    clean = subprocess.run(command, check=False, capture_output=True, text=True)
    assert clean.returncode == 0
    assert json.loads(output_path.read_text())["status"] == "clean"

    failed = artifact([call(runtime_state="failed")])
    artifact_path.write_text(json.dumps(failed), encoding="utf-8")
    policy_rejection = subprocess.run(command, check=False, capture_output=True, text=True)
    assert policy_rejection.returncode == 2
    assert json.loads(output_path.read_text())["status"] == "reconciliation_required"

    artifact_path.write_text("{", encoding="utf-8")
    malformed = subprocess.run(command, check=False, capture_output=True, text=True)
    assert malformed.returncode == 3
    assert json.loads(output_path.read_text())["status"] == "malformed"


def test_thousand_call_artifact_is_bounded_and_deterministic() -> None:
    calls = []
    for index in range(1_000):
        item = call(call_id=f"call-{index}", effect_kind="none", receipts=[])
        calls.append(item)
    value = artifact(calls)
    report = audit_artifact(value, as_of=AS_OF)
    assert report.accepted is True
    assert report.call_count == 1_000


def test_policy_digest_changes_when_limits_change() -> None:
    default = audit_artifact(artifact(), as_of=AS_OF)
    stricter = audit_artifact(
        deepcopy(artifact()),
        as_of=AS_OF,
        policy=ReconciliationPolicy(max_calls=999),
    )
    assert default.policy_sha256 != stricter.policy_sha256
