from __future__ import annotations

import json
import math

import pytest

from src.governed_runtime import (
    ActionResult,
    ActionStatus,
    Decision,
    ExecutionTrace,
    PolicyResult,
)
from src.runtime_eval import (
    RuntimeEvaluationError,
    RuntimeGatePolicy,
    evaluate_traces,
)


def _result(action_id: str, status: ActionStatus) -> ActionResult:
    decision = {
        ActionStatus.AWAITING_APPROVAL: Decision.REQUIRE_APPROVAL,
        ActionStatus.DENIED: Decision.DENY,
        ActionStatus.SKIPPED_BUDGET: Decision.DENY,
    }.get(status, Decision.ALLOW)
    return ActionResult(
        action_id=action_id,
        tool="private-tool-name",
        status=status,
        output=(
            {"private": "payload"} if status in {ActionStatus.SUCCEEDED, ActionStatus.REPLAYED} else None
        ),
        error="private-error" if status is ActionStatus.FAILED else None,
        policy=PolicyResult(decision, "private-policy-reason"),
        idempotency_key="private-ledger-key",
    )


def _trace(
    name: str,
    statuses: list[ActionStatus],
    *,
    stopped_reason: str = "plan_completed",
) -> ExecutionTrace:
    return ExecutionTrace(
        task=f"private-task-{name}",
        planned_actions=len(statuses),
        max_steps=max(1, len(statuses)),
        results=[_result(f"{name}-{index}", status) for index, status in enumerate(statuses)],
        stopped_reason=stopped_reason,
    )


def test_aggregate_gate_passes_prespecified_operational_bounds() -> None:
    traces = [
        _trace(
            "complete",
            [
                ActionStatus.SUCCEEDED,
                ActionStatus.SUCCEEDED,
                ActionStatus.FAILED,
                ActionStatus.REPLAYED,
            ],
        ),
        _trace(
            "budget",
            [ActionStatus.AWAITING_APPROVAL, ActionStatus.SKIPPED_BUDGET],
            stopped_reason="step_budget_exhausted",
        ),
    ]
    policy = RuntimeGatePolicy(
        minimum_planned_actions=6,
        minimum_success_rate=0.3,
        maximum_failure_rate=0.2,
        maximum_approval_rate=0.2,
        maximum_denial_rate=0.0,
        maximum_replay_rate=0.2,
        maximum_budget_skip_rate=0.2,
        minimum_completed_trace_rate=0.5,
    )

    report = evaluate_traces(traces, policy)

    assert report.passed
    assert report.violations == ()
    assert report.metrics.trace_count == 2
    assert report.metrics.planned_actions == 6
    assert report.metrics.executed_actions == 4
    assert report.metrics.success_rate == pytest.approx(2 / 6)
    assert report.metrics.completed_trace_rate == 0.5
    assert len(report.policy_sha256) == 64
    assert report.to_dict()["policy_sha256"] == policy.sha256


def test_gate_reports_all_threshold_violations_without_trace_payloads() -> None:
    trace = _trace(
        "sensitive",
        [
            ActionStatus.FAILED,
            ActionStatus.AWAITING_APPROVAL,
            ActionStatus.DENIED,
            ActionStatus.REPLAYED,
            ActionStatus.SKIPPED_BUDGET,
        ],
        stopped_reason="step_budget_exhausted",
    )
    policy = RuntimeGatePolicy(
        minimum_planned_actions=6,
        minimum_success_rate=0.5,
        maximum_failure_rate=0.0,
        maximum_approval_rate=0.0,
        maximum_denial_rate=0.0,
        maximum_replay_rate=0.0,
        maximum_budget_skip_rate=0.0,
        minimum_completed_trace_rate=1.0,
    )

    report = evaluate_traces([trace], policy)

    assert not report.passed
    assert report.violations == (
        "minimum_planned_actions_not_met",
        "success_rate_below_minimum",
        "failure_rate_above_maximum",
        "approval_rate_above_maximum",
        "denial_rate_above_maximum",
        "replay_rate_above_maximum",
        "budget_skip_rate_above_maximum",
        "completed_trace_rate_below_minimum",
    )
    serialized = json.dumps(report.to_dict(), sort_keys=True)
    assert "runtime-evaluation-gate/v1" in serialized
    for private_value in (
        "private-task",
        "private-tool-name",
        "private-ledger-key",
        "private-policy-reason",
        "private-error",
        "payload",
    ):
        assert private_value not in serialized


@pytest.mark.parametrize(
    ("trace", "code"),
    [
        (
            ExecutionTrace(
                task="missing result",
                planned_actions=2,
                max_steps=2,
                results=[_result("one", ActionStatus.SUCCEEDED)],
                stopped_reason="plan_completed",
            ),
            "trace_shape_invalid",
        ),
        (
            ExecutionTrace(
                task="duplicate result",
                planned_actions=2,
                max_steps=2,
                results=[
                    _result("same", ActionStatus.SUCCEEDED),
                    _result("same", ActionStatus.SUCCEEDED),
                ],
                stopped_reason="plan_completed",
            ),
            "trace_result_invalid",
        ),
        (
            ExecutionTrace(
                task="policy contradiction",
                planned_actions=1,
                max_steps=1,
                results=[
                    ActionResult(
                        action_id="denied-but-allowed",
                        tool="tool",
                        status=ActionStatus.DENIED,
                        output=None,
                        error=None,
                        policy=PolicyResult(Decision.ALLOW, "contradiction"),
                        idempotency_key="key",
                    )
                ],
                stopped_reason="plan_completed",
            ),
            "trace_result_inconsistent",
        ),
        (
            ExecutionTrace(
                task="non-result member",
                planned_actions=1,
                max_steps=1,
                results=[object()],  # type: ignore[list-item]
                stopped_reason="plan_completed",
            ),
            "trace_result_invalid",
        ),
        (
            ExecutionTrace(
                task="invalid unicode",
                planned_actions=1,
                max_steps=1,
                results=[_result("invalid-\ud800", ActionStatus.SUCCEEDED)],
                stopped_reason="plan_completed",
            ),
            "trace_result_invalid",
        ),
        (
            _trace("wrong-stop", [ActionStatus.SKIPPED_BUDGET]),
            "trace_stop_reason_inconsistent",
        ),
        (
            ExecutionTrace(
                task="unknown stop",
                planned_actions=0,
                max_steps=1,
                stopped_reason="cancelled",
            ),
            "trace_stop_reason_invalid",
        ),
    ],
)
def test_gate_rejects_incomplete_or_inconsistent_traces(
    trace: ExecutionTrace,
    code: str,
) -> None:
    with pytest.raises(RuntimeEvaluationError, match=code):
        evaluate_traces([trace], RuntimeGatePolicy())


@pytest.mark.parametrize(
    "overrides",
    [
        {"minimum_planned_actions": True},
        {"minimum_planned_actions": 0},
        {"minimum_planned_actions": 1_000_001},
        {"minimum_success_rate": math.nan},
        {"minimum_success_rate": -0.1},
        {"maximum_failure_rate": 1.1},
        {"maximum_approval_rate": True},
        {"minimum_completed_trace_rate": math.inf},
    ],
)
def test_policy_rejects_unsafe_or_nonfinite_bounds(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        RuntimeGatePolicy(**overrides)  # type: ignore[arg-type]


def test_policy_digest_changes_with_prespecified_thresholds() -> None:
    baseline = RuntimeGatePolicy(minimum_planned_actions=100)
    stricter = RuntimeGatePolicy(
        minimum_planned_actions=100,
        maximum_failure_rate=0.01,
    )

    assert baseline.sha256 != stricter.sha256
    assert baseline.sha256 == RuntimeGatePolicy(minimum_planned_actions=100).sha256


@pytest.mark.parametrize("traces", [[], "not-a-trace-set", b"not-a-trace-set"])
def test_gate_requires_a_bounded_nonempty_trace_sequence(traces: object) -> None:
    with pytest.raises(RuntimeEvaluationError, match="trace_set_size_invalid"):
        evaluate_traces(traces, RuntimeGatePolicy())  # type: ignore[arg-type]


def test_gate_rejects_non_trace_members_and_wrong_policy_type() -> None:
    with pytest.raises(RuntimeEvaluationError, match="trace_type_invalid"):
        evaluate_traces([object()], RuntimeGatePolicy())  # type: ignore[list-item]
    with pytest.raises(TypeError, match="policy must be RuntimeGatePolicy"):
        evaluate_traces([_trace("valid", [])], object())  # type: ignore[arg-type]
