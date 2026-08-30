from __future__ import annotations

from dataclasses import asdict, dataclass

from src.governed_runtime import ActionStatus, ExecutionTrace


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
