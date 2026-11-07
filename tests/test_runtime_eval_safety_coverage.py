from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from src.governed_runtime import (
    ActionResult,
    ActionStatus,
    Decision,
    ExecutionTrace,
    PolicyResult,
)
from src.runtime_eval import RuntimeEvaluationError
from src.runtime_eval_safety_coverage import (
    SAFETY_COVERAGE_SCHEMA,
    SafetyBoundary,
    SafetyCoverageError,
    SafetyCoveragePolicy,
    SafetyProbe,
    audit_runtime_safety_coverage,
    safety_probe_set_sha256,
)


def _result(
    action_id: str,
    status: ActionStatus,
    decision: Decision,
) -> ActionResult:
    if status in {ActionStatus.SUCCEEDED, ActionStatus.REPLAYED}:
        output, error = {"private": "payload"}, None
    elif status is ActionStatus.FAILED:
        output, error = None, "private failure"
    else:
        output, error = None, None
    return ActionResult(
        action_id=action_id,
        tool="private-tool",
        status=status,
        output=output,
        error=error,
        policy=PolicyResult(decision, "private policy reason"),
        idempotency_key="private-idempotency-key",
    )


def _fixture() -> tuple[list[ExecutionTrace], tuple[SafetyProbe, ...]]:
    specifications = (
        (
            SafetyBoundary.AUTONOMOUS_SUCCESS,
            ActionStatus.SUCCEEDED,
            Decision.ALLOW,
            "plan_completed",
        ),
        (
            SafetyBoundary.NORMALIZED_TOOL_FAILURE,
            ActionStatus.FAILED,
            Decision.ALLOW,
            "plan_completed",
        ),
        (
            SafetyBoundary.APPROVAL_WITHHELD,
            ActionStatus.AWAITING_APPROVAL,
            Decision.REQUIRE_APPROVAL,
            "plan_completed",
        ),
        (
            SafetyBoundary.APPROVAL_GRANTED,
            ActionStatus.SUCCEEDED,
            Decision.REQUIRE_APPROVAL,
            "plan_completed",
        ),
        (
            SafetyBoundary.POLICY_DENIAL,
            ActionStatus.DENIED,
            Decision.DENY,
            "plan_completed",
        ),
        (
            SafetyBoundary.REPLAY_SUPPRESSION,
            ActionStatus.REPLAYED,
            Decision.ALLOW,
            "plan_completed",
        ),
        (
            SafetyBoundary.STEP_BUDGET_ENFORCEMENT,
            ActionStatus.SKIPPED_BUDGET,
            Decision.DENY,
            "step_budget_exhausted",
        ),
        (
            SafetyBoundary.UNKNOWN_TOOL_DENIAL,
            ActionStatus.DENIED,
            Decision.DENY,
            "plan_completed",
        ),
    )
    traces: list[ExecutionTrace] = []
    probes: list[SafetyProbe] = []
    for index, (boundary, status, decision, stop_reason) in enumerate(specifications):
        traces.append(
            ExecutionTrace(
                task=f"private task {index}",
                planned_actions=1,
                max_steps=1,
                results=[_result(f"action-{index}", status, decision)],
                stopped_reason=stop_reason,
            )
        )
        probes.append(
            SafetyProbe(
                boundary,
                index,
                0,
                status,
                decision,
                stop_reason,
            )
        )
    return traces, tuple(probes)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def test_audits_every_required_boundary_with_private_receipt() -> None:
    traces, probes = _fixture()
    receipt = audit_runtime_safety_coverage(
        traces,
        probes,
        SafetyCoveragePolicy(),
    )

    assert receipt["schema_version"] == SAFETY_COVERAGE_SCHEMA
    assert receipt["status"] == "pass"
    assert receipt["trace_count"] == 8
    assert receipt["probe_count"] == 8
    assert set(receipt["boundary_witness_counts"].values()) == {1}
    digest = receipt.pop("evidence_sha256")
    assert digest == hashlib.sha256(_canonical(receipt)).hexdigest()
    serialized = json.dumps(receipt)
    for private in (
        "private task",
        "private-tool",
        "private failure",
        "private policy reason",
        "private-idempotency-key",
        "payload",
    ):
        assert private not in serialized


@pytest.mark.parametrize(
    "replacement",
    [
        {"expected_status": ActionStatus.FAILED},
        {"expected_decision": Decision.DENY},
        {"expected_stop_reason": "step_budget_exhausted"},
    ],
)
def test_rejects_probe_that_does_not_match_observed_control(
    replacement: dict[str, object],
) -> None:
    traces, probes = _fixture()
    changed = (replace(probes[0], **replacement), *probes[1:])
    with pytest.raises(SafetyCoverageError, match="probe_witness_mismatch"):
        audit_runtime_safety_coverage(traces, changed, SafetyCoveragePolicy())


def test_rejects_missing_required_boundary() -> None:
    traces, probes = _fixture()
    with pytest.raises(SafetyCoverageError, match="required_boundary_missing"):
        audit_runtime_safety_coverage(traces, probes[:-1], SafetyCoveragePolicy())


def test_rejects_out_of_range_and_reused_probe_coordinates() -> None:
    traces, probes = _fixture()
    out_of_range = (replace(probes[0], trace_index=len(traces)), *probes[1:])
    with pytest.raises(SafetyCoverageError, match="probe_out_of_range"):
        audit_runtime_safety_coverage(traces, out_of_range, SafetyCoveragePolicy())

    reused = (probes[0], replace(probes[1], trace_index=0))
    with pytest.raises(SafetyCoverageError, match="probe_coordinate_reused"):
        audit_runtime_safety_coverage(
            traces,
            reused,
            SafetyCoveragePolicy(
                required_boundaries=frozenset(
                    {
                        SafetyBoundary.AUTONOMOUS_SUCCESS,
                        SafetyBoundary.NORMALIZED_TOOL_FAILURE,
                    }
                )
            ),
        )


def test_trace_validation_precedes_probe_dereference() -> None:
    traces, probes = _fixture()
    traces[0].results[0] = replace(traces[0].results[0], output=None)
    with pytest.raises(RuntimeEvaluationError, match="trace_result_inconsistent"):
        audit_runtime_safety_coverage(traces, probes, SafetyCoveragePolicy())


def test_probe_set_commitment_binds_order_and_expectations() -> None:
    _traces, probes = _fixture()
    original = safety_probe_set_sha256(probes)
    assert len(original) == 64
    assert safety_probe_set_sha256(tuple(reversed(probes))) != original
    assert (
        safety_probe_set_sha256((replace(probes[0], expected_status=ActionStatus.FAILED), *probes[1:]))
        != original
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"required_boundaries": frozenset()},
        {"required_boundaries": frozenset({"not-a-boundary"})},
        {"minimum_witnesses_per_boundary": 0},
        {"minimum_witnesses_per_boundary": True},
    ],
)
def test_policy_rejects_invalid_contracts(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        SafetyCoveragePolicy(**kwargs)


def test_probe_rejects_invalid_indices_and_stop_reason() -> None:
    with pytest.raises(ValueError, match="trace_index"):
        SafetyProbe(
            SafetyBoundary.POLICY_DENIAL,
            -1,
            0,
            ActionStatus.DENIED,
            Decision.DENY,
            "plan_completed",
        )
    with pytest.raises(ValueError, match="stop_reason"):
        SafetyProbe(
            SafetyBoundary.POLICY_DENIAL,
            0,
            0,
            ActionStatus.DENIED,
            Decision.DENY,
            "unknown",
        )
