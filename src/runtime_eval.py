from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass

from src.governed_runtime import (
    ActionResult,
    ActionStatus,
    Decision,
    ExecutionTrace,
    PolicyResult,
)

MAX_EVALUATION_TRACES = 10_000
MAX_EVALUATION_ACTIONS = 1_000_000


class RuntimeEvaluationError(RuntimeError):
    """A trace set cannot be evaluated without weakening the gate."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RuntimeMetrics:
    planned_actions: int
    executed_actions: int
    success_rate: float
    failure_rate: float
    approval_rate: float
    denial_rate: float
    replay_rate: float
    budget_skip_rate: float
    completed_plan: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuntimeGatePolicy:
    """Prespecified aggregate bounds for a runtime benchmark release."""

    minimum_planned_actions: int = 1
    minimum_success_rate: float = 0.0
    maximum_failure_rate: float = 1.0
    maximum_approval_rate: float = 1.0
    maximum_denial_rate: float = 1.0
    maximum_replay_rate: float = 1.0
    maximum_budget_skip_rate: float = 1.0
    minimum_completed_trace_rate: float = 0.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.minimum_planned_actions, bool)
            or not isinstance(self.minimum_planned_actions, int)
            or not 1 <= self.minimum_planned_actions <= MAX_EVALUATION_ACTIONS
        ):
            raise ValueError("minimum_planned_actions must be an integer in [1, 1000000]")
        for name in (
            "minimum_success_rate",
            "maximum_failure_rate",
            "maximum_approval_rate",
            "maximum_denial_rate",
            "maximum_replay_rate",
            "maximum_budget_skip_rate",
            "minimum_completed_trace_rate",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0.0 <= value <= 1.0
            ):
                raise ValueError(f"{name} must be finite and in [0, 1]")

    @property
    def sha256(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(b"runtime-evaluation-policy/v1\0" + payload).hexdigest()


@dataclass(frozen=True, slots=True)
class AggregateRuntimeMetrics:
    trace_count: int
    planned_actions: int
    executed_actions: int
    succeeded_actions: int
    failed_actions: int
    awaiting_approval_actions: int
    denied_actions: int
    replayed_actions: int
    budget_skipped_actions: int
    success_rate: float
    failure_rate: float
    approval_rate: float
    denial_rate: float
    replay_rate: float
    budget_skip_rate: float
    completed_trace_rate: float


@dataclass(frozen=True, slots=True)
class RuntimeGateReport:
    """Aggregate-only release decision without trace payloads or identities."""

    metrics: AggregateRuntimeMetrics
    policy_sha256: str
    violations: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "runtime-evaluation-gate/v1",
            "passed": self.passed,
            "policy_sha256": self.policy_sha256,
            "violations": list(self.violations),
            "metrics": asdict(self.metrics),
        }


def evaluate_trace(trace: ExecutionTrace) -> RuntimeMetrics:
    total = trace.planned_actions
    if total == 0:
        return RuntimeMetrics(
            planned_actions=0,
            executed_actions=0,
            success_rate=0.0,
            failure_rate=0.0,
            approval_rate=0.0,
            denial_rate=0.0,
            replay_rate=0.0,
            budget_skip_rate=0.0,
            completed_plan=trace.stopped_reason == "plan_completed",
        )

    counts = {status: 0 for status in ActionStatus}
    for result in trace.results:
        counts[result.status] += 1

    executed = counts[ActionStatus.SUCCEEDED] + counts[ActionStatus.FAILED] + counts[ActionStatus.REPLAYED]
    return RuntimeMetrics(
        planned_actions=total,
        executed_actions=executed,
        success_rate=counts[ActionStatus.SUCCEEDED] / total,
        failure_rate=counts[ActionStatus.FAILED] / total,
        approval_rate=counts[ActionStatus.AWAITING_APPROVAL] / total,
        denial_rate=counts[ActionStatus.DENIED] / total,
        replay_rate=counts[ActionStatus.REPLAYED] / total,
        budget_skip_rate=counts[ActionStatus.SKIPPED_BUDGET] / total,
        completed_plan=trace.stopped_reason == "plan_completed",
    )


def _validated_counts(trace: ExecutionTrace) -> dict[ActionStatus, int]:
    if (
        isinstance(trace.planned_actions, bool)
        or not isinstance(trace.planned_actions, int)
        or not 0 <= trace.planned_actions <= MAX_EVALUATION_ACTIONS
        or isinstance(trace.max_steps, bool)
        or not isinstance(trace.max_steps, int)
        or not 1 <= trace.max_steps <= MAX_EVALUATION_ACTIONS
        or not isinstance(trace.results, list)
        or len(trace.results) != trace.planned_actions
    ):
        raise RuntimeEvaluationError("trace_shape_invalid")
    if trace.stopped_reason not in {"plan_completed", "step_budget_exhausted"}:
        raise RuntimeEvaluationError("trace_stop_reason_invalid")

    counts = {status: 0 for status in ActionStatus}
    action_ids: set[str] = set()
    for result in trace.results:
        if not isinstance(result, ActionResult):
            raise RuntimeEvaluationError("trace_result_invalid")
        try:
            encoded_action_id = result.action_id.encode("utf-8")
        except (AttributeError, UnicodeEncodeError):
            raise RuntimeEvaluationError("trace_result_invalid") from None
        if (
            not isinstance(result.action_id, str)
            or not result.action_id
            or len(encoded_action_id) > 512
            or result.action_id in action_ids
            or not isinstance(result.status, ActionStatus)
            or not isinstance(result.policy, PolicyResult)
            or not isinstance(result.policy.decision, Decision)
        ):
            raise RuntimeEvaluationError("trace_result_invalid")
        if result.status in {
            ActionStatus.SUCCEEDED,
            ActionStatus.FAILED,
            ActionStatus.REPLAYED,
        }:
            if result.policy.decision is Decision.DENY:
                raise RuntimeEvaluationError("trace_result_inconsistent")
        elif result.status is ActionStatus.AWAITING_APPROVAL:
            if result.policy.decision is not Decision.REQUIRE_APPROVAL:
                raise RuntimeEvaluationError("trace_result_inconsistent")
        elif result.policy.decision is not Decision.DENY:
            raise RuntimeEvaluationError("trace_result_inconsistent")

        if result.status in {ActionStatus.SUCCEEDED, ActionStatus.REPLAYED}:
            valid_outcome = isinstance(result.output, dict) and result.error is None
        elif result.status is ActionStatus.FAILED:
            valid_outcome = result.output is None and isinstance(result.error, str) and bool(result.error)
        elif result.status is ActionStatus.DENIED:
            valid_outcome = result.output is None and (result.error is None or isinstance(result.error, str))
        else:
            valid_outcome = result.output is None and result.error is None
        if not valid_outcome:
            raise RuntimeEvaluationError("trace_result_inconsistent")
        action_ids.add(result.action_id)
        counts[result.status] += 1

    has_budget_skip = counts[ActionStatus.SKIPPED_BUDGET] > 0
    if has_budget_skip != (trace.stopped_reason == "step_budget_exhausted"):
        raise RuntimeEvaluationError("trace_stop_reason_inconsistent")
    return counts


def evaluate_traces(
    traces: Sequence[ExecutionTrace],
    policy: RuntimeGatePolicy,
) -> RuntimeGateReport:
    """Validate and gate a bounded trace set using aggregate operational rates."""

    if not isinstance(policy, RuntimeGatePolicy):
        raise TypeError("policy must be RuntimeGatePolicy")
    if (
        not isinstance(traces, Sequence)
        or isinstance(traces, (str, bytes))
        or not 1 <= len(traces) <= MAX_EVALUATION_TRACES
    ):
        raise RuntimeEvaluationError("trace_set_size_invalid")

    totals = {status: 0 for status in ActionStatus}
    total_actions = 0
    completed_traces = 0
    for trace in traces:
        if not isinstance(trace, ExecutionTrace):
            raise RuntimeEvaluationError("trace_type_invalid")
        counts = _validated_counts(trace)
        total_actions += trace.planned_actions
        if total_actions > MAX_EVALUATION_ACTIONS:
            raise RuntimeEvaluationError("trace_action_limit_exceeded")
        completed_traces += trace.stopped_reason == "plan_completed"
        for status, count in counts.items():
            totals[status] += count

    denominator = total_actions or 1
    trace_denominator = len(traces)
    succeeded = totals[ActionStatus.SUCCEEDED]
    failed = totals[ActionStatus.FAILED]
    approvals = totals[ActionStatus.AWAITING_APPROVAL]
    denied = totals[ActionStatus.DENIED]
    replayed = totals[ActionStatus.REPLAYED]
    budget_skipped = totals[ActionStatus.SKIPPED_BUDGET]
    metrics = AggregateRuntimeMetrics(
        trace_count=len(traces),
        planned_actions=total_actions,
        executed_actions=succeeded + failed + replayed,
        succeeded_actions=succeeded,
        failed_actions=failed,
        awaiting_approval_actions=approvals,
        denied_actions=denied,
        replayed_actions=replayed,
        budget_skipped_actions=budget_skipped,
        success_rate=succeeded / denominator,
        failure_rate=failed / denominator,
        approval_rate=approvals / denominator,
        denial_rate=denied / denominator,
        replay_rate=replayed / denominator,
        budget_skip_rate=budget_skipped / denominator,
        completed_trace_rate=completed_traces / trace_denominator,
    )

    violations: list[str] = []
    comparisons = (
        (
            total_actions < policy.minimum_planned_actions,
            "minimum_planned_actions_not_met",
        ),
        (metrics.success_rate < policy.minimum_success_rate, "success_rate_below_minimum"),
        (metrics.failure_rate > policy.maximum_failure_rate, "failure_rate_above_maximum"),
        (metrics.approval_rate > policy.maximum_approval_rate, "approval_rate_above_maximum"),
        (metrics.denial_rate > policy.maximum_denial_rate, "denial_rate_above_maximum"),
        (metrics.replay_rate > policy.maximum_replay_rate, "replay_rate_above_maximum"),
        (
            metrics.budget_skip_rate > policy.maximum_budget_skip_rate,
            "budget_skip_rate_above_maximum",
        ),
        (
            metrics.completed_trace_rate < policy.minimum_completed_trace_rate,
            "completed_trace_rate_below_minimum",
        ),
    )
    violations.extend(code for failed_check, code in comparisons if failed_check)
    return RuntimeGateReport(
        metrics=metrics,
        policy_sha256=policy.sha256,
        violations=tuple(violations),
    )
