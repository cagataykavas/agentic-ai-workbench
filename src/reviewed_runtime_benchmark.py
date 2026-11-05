from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from src.governed_runtime import (
    ActionStatus,
    ExecutionTrace,
    GovernedAgentRuntime,
    PlannedAction,
    PolicyConfig,
    RiskLevel,
    SideEffect,
    ToolPolicy,
    ToolRegistry,
    ToolSpec,
)
from src.runtime_eval import RuntimeGatePolicy, RuntimeGateReport
from src.runtime_eval_manifest import (
    RuntimeBenchmarkManifest,
    evaluate_and_sign_runtime_benchmark,
)

RUNTIME_VERSION = "agent-runtime-0.2.0"
SCENARIO_SUITE_SCHEMA = "reviewed-governed-runtime-suite/v1"


class ReviewedRuntimeBenchmarkError(RuntimeError):
    """The reviewed benchmark could not be reconstructed exactly."""


@dataclass(frozen=True, slots=True)
class ReviewedScenario:
    name: str
    actions: tuple[PlannedAction, ...]
    expected_statuses: tuple[ActionStatus, ...]
    max_steps: int = 8
    approved_action_ids: frozenset[str] = frozenset()


def _action(
    action_id: str,
    tool: str,
    value: int,
    *,
    idempotency_key: str | None = None,
) -> PlannedAction:
    return PlannedAction(
        action_id=action_id,
        tool=tool,
        arguments={"value": value},
        rationale="reviewed deterministic runtime benchmark",
        idempotency_key=idempotency_key,
    )


REVIEWED_SCENARIOS = (
    ReviewedScenario(
        name="safe-read-sequence",
        actions=(_action("read-1", "lookup", 1), _action("read-2", "lookup", 2)),
        expected_statuses=(ActionStatus.SUCCEEDED, ActionStatus.SUCCEEDED),
    ),
    ReviewedScenario(
        name="tool-failure",
        actions=(_action("fail-1", "unstable", 3),),
        expected_statuses=(ActionStatus.FAILED,),
    ),
    ReviewedScenario(
        name="approval-required",
        actions=(_action("publish-1", "publish", 4),),
        expected_statuses=(ActionStatus.AWAITING_APPROVAL,),
    ),
    ReviewedScenario(
        name="approved-side-effect",
        actions=(_action("publish-2", "publish", 5),),
        approved_action_ids=frozenset({"publish-2"}),
        expected_statuses=(ActionStatus.SUCCEEDED,),
    ),
    ReviewedScenario(
        name="policy-denial",
        actions=(_action("denied-1", "denied", 6),),
        expected_statuses=(ActionStatus.DENIED,),
    ),
    ReviewedScenario(
        name="idempotent-replay",
        actions=(
            _action("replay-1", "lookup", 7, idempotency_key="reviewed-replay-key"),
            _action("replay-2", "lookup", 7, idempotency_key="reviewed-replay-key"),
        ),
        expected_statuses=(ActionStatus.SUCCEEDED, ActionStatus.REPLAYED),
    ),
    ReviewedScenario(
        name="step-budget",
        actions=(
            _action("budget-1", "lookup", 8),
            _action("budget-2", "lookup", 9),
            _action("budget-3", "lookup", 10),
        ),
        max_steps=1,
        expected_statuses=(
            ActionStatus.SUCCEEDED,
            ActionStatus.SKIPPED_BUDGET,
            ActionStatus.SKIPPED_BUDGET,
        ),
    ),
    ReviewedScenario(
        name="unknown-tool",
        actions=(_action("unknown-1", "not-registered", 11),),
        expected_statuses=(ActionStatus.DENIED,),
    ),
)


def reviewed_runtime_policy() -> RuntimeGatePolicy:
    """Return the prespecified operational bounds for the reviewed suite."""
    return RuntimeGatePolicy(
        minimum_planned_actions=12,
        minimum_success_rate=0.40,
        maximum_failure_rate=0.10,
        maximum_approval_rate=0.10,
        maximum_denial_rate=0.20,
        maximum_replay_rate=0.10,
        maximum_budget_skip_rate=0.20,
        minimum_completed_trace_rate=0.85,
    )


def reviewed_scenario_suite_sha256() -> str:
    """Commit to exact scenario inputs and expected runtime outcomes."""
    scenarios = []
    for scenario in REVIEWED_SCENARIOS:
        actions = []
        for action in scenario.actions:
            arguments = json.dumps(
                action.arguments,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            actions.append(
                {
                    "action_id": action.action_id,
                    "arguments_sha256": hashlib.sha256(arguments).hexdigest(),
                    "idempotency_key_sha256": (
                        hashlib.sha256(action.idempotency_key.encode()).hexdigest()
                        if action.idempotency_key is not None
                        else None
                    ),
                    "tool_sha256": hashlib.sha256(action.tool.encode()).hexdigest(),
                }
            )
        scenarios.append(
            {
                "actions": actions,
                "approved_action_ids": sorted(scenario.approved_action_ids),
                "expected_statuses": [status.value for status in scenario.expected_statuses],
                "max_steps": scenario.max_steps,
                "name": scenario.name,
            }
        )
    document = {
        "policy_sha256": reviewed_runtime_policy().sha256,
        "scenarios": scenarios,
        "schema_version": SCENARIO_SUITE_SCHEMA,
    }
    payload = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="lookup",
            description="return one deterministic local record",
            handler=lambda arguments: {"observed": arguments["value"]},
        )
    )

    def fail(_arguments: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("controlled benchmark failure")

    registry.register(
        ToolSpec(
            name="unstable",
            description="exercise normalized tool failure",
            handler=fail,
        )
    )
    registry.register(
        ToolSpec(
            name="publish",
            description="exercise explicit approval",
            handler=lambda arguments: {"published": arguments["value"]},
            risk=RiskLevel.HIGH,
            side_effect=SideEffect.IRREVERSIBLE,
        )
    )
    registry.register(
        ToolSpec(
            name="denied",
            description="exercise policy denial",
            handler=lambda arguments: {"unexpected": arguments["value"]},
        )
    )
    return registry


def run_reviewed_runtime_benchmark() -> tuple[list[ExecutionTrace], RuntimeGatePolicy]:
    """Execute the reviewed suite and fail if runtime behavior drifts."""
    traces = []
    for scenario in REVIEWED_SCENARIOS:
        runtime = GovernedAgentRuntime(
            _registry(),
            policy=ToolPolicy(PolicyConfig(denied_tools=frozenset({"denied"}))),
            max_steps=scenario.max_steps,
        )
        trace = runtime.execute(
            task=f"reviewed-scenario:{scenario.name}",
            plan=list(scenario.actions),
            approved_action_ids=scenario.approved_action_ids,
        )
        observed = tuple(result.status for result in trace.results)
        if observed != scenario.expected_statuses:
            raise ReviewedRuntimeBenchmarkError(f"scenario outcome drifted: {scenario.name}")
        expected_stop = (
            "step_budget_exhausted"
            if ActionStatus.SKIPPED_BUDGET in scenario.expected_statuses
            else "plan_completed"
        )
        if trace.stopped_reason != expected_stop:
            raise ReviewedRuntimeBenchmarkError(f"scenario stop reason drifted: {scenario.name}")
        traces.append(trace)
    return traces, reviewed_runtime_policy()


def sign_reviewed_runtime_benchmark(
    *,
    source_revision: str,
    key_id: str,
    secret: bytes,
    runtime_version: str = RUNTIME_VERSION,
) -> tuple[RuntimeGateReport, RuntimeBenchmarkManifest]:
    """Reconstruct, gate, and sign the reviewed suite inside one trust boundary."""
    traces, policy = run_reviewed_runtime_benchmark()
    report, manifest = evaluate_and_sign_runtime_benchmark(
        traces,
        policy,
        scenario_suite_sha256=reviewed_scenario_suite_sha256(),
        runtime_version=runtime_version,
        source_revision=source_revision,
        key_id=key_id,
        secret=secret,
    )
    if not report.passed:
        raise ReviewedRuntimeBenchmarkError("reviewed runtime gate failed")
    return report, manifest
