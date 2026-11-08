from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import Enum

from src.governed_runtime import (
    Decision,
    ExecutionTrace,
    GovernedAgentRuntime,
    PolicyConfig,
    PolicyResult,
    ToolPolicy,
    ToolRegistry,
    ToolSpec,
)
from src.reviewed_runtime_benchmark import (
    REVIEWED_SCENARIOS,
    ReviewedScenario,
    build_reviewed_runtime_registry,
    reviewed_safety_probes,
)
from src.runtime_eval_safety_coverage import SafetyBoundary

MUTATION_CAMPAIGN_SCHEMA = "runtime-safety-mutation-campaign/v1"


class RuntimeSafetyMutant(str, Enum):
    """Single-fault unsafe variants supported by the reviewed campaign."""

    TOOL_FAILURE_MASKED = "tool_failure_masked"
    APPROVAL_BYPASSED = "approval_bypassed"
    POLICY_DENIAL_BYPASSED = "policy_denial_bypassed"
    REPLAY_SUPPRESSION_BYPASSED = "replay_suppression_bypassed"
    STEP_BUDGET_BYPASSED = "step_budget_bypassed"
    UNKNOWN_TOOL_ALLOWED = "unknown_tool_allowed"


MUTANT_BOUNDARIES = {
    RuntimeSafetyMutant.TOOL_FAILURE_MASKED: SafetyBoundary.NORMALIZED_TOOL_FAILURE,
    RuntimeSafetyMutant.APPROVAL_BYPASSED: SafetyBoundary.APPROVAL_WITHHELD,
    RuntimeSafetyMutant.POLICY_DENIAL_BYPASSED: SafetyBoundary.POLICY_DENIAL,
    RuntimeSafetyMutant.REPLAY_SUPPRESSION_BYPASSED: SafetyBoundary.REPLAY_SUPPRESSION,
    RuntimeSafetyMutant.STEP_BUDGET_BYPASSED: SafetyBoundary.STEP_BUDGET_ENFORCEMENT,
    RuntimeSafetyMutant.UNKNOWN_TOOL_ALLOWED: SafetyBoundary.UNKNOWN_TOOL_DENIAL,
}
SUPPORTED_MUTANTS = tuple(RuntimeSafetyMutant)


class MutationCampaignError(RuntimeError):
    """The reviewed suite failed to kill every declared unsafe mutant."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class MutationOutcome:
    mutant: RuntimeSafetyMutant
    expected_boundary: SafetyBoundary
    detected_boundary: SafetyBoundary | None
    killed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.mutant, RuntimeSafetyMutant):
            raise TypeError("mutant must be RuntimeSafetyMutant")
        if not isinstance(self.expected_boundary, SafetyBoundary):
            raise TypeError("expected_boundary must be SafetyBoundary")
        if self.detected_boundary is not None and not isinstance(self.detected_boundary, SafetyBoundary):
            raise TypeError("detected_boundary must be SafetyBoundary or None")
        if not isinstance(self.killed, bool):
            raise TypeError("killed must be bool")
        if self.killed != (self.detected_boundary is not None):
            raise ValueError("killed must match detected_boundary presence")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


class _ApprovalBypassPolicy(ToolPolicy):
    def evaluate(self, tool: ToolSpec) -> PolicyResult:
        result = super().evaluate(tool)
        if result.decision is Decision.REQUIRE_APPROVAL:
            return PolicyResult(Decision.ALLOW, "mutation: approval bypassed")
        return result


def _registry(mutant: RuntimeSafetyMutant) -> ToolRegistry:
    original = build_reviewed_runtime_registry()
    registry = ToolRegistry()
    for name in original.names:
        tool = original.get(name)
        if mutant is RuntimeSafetyMutant.TOOL_FAILURE_MASKED and name == "unstable":
            tool = replace(tool, handler=lambda arguments: {"masked": arguments["value"]})
        if mutant is RuntimeSafetyMutant.REPLAY_SUPPRESSION_BYPASSED and name == "lookup":
            tool = replace(tool, idempotent=False)
        registry.register(tool)
    if mutant is RuntimeSafetyMutant.UNKNOWN_TOOL_ALLOWED:
        registry.register(
            ToolSpec(
                name="not-registered",
                description="mutation: unknown tool admitted",
                handler=lambda arguments: {"unexpected": arguments["value"]},
            )
        )
    return registry


def _runtime(mutant: RuntimeSafetyMutant, scenario: ReviewedScenario) -> GovernedAgentRuntime:
    if mutant is RuntimeSafetyMutant.APPROVAL_BYPASSED:
        policy: ToolPolicy = _ApprovalBypassPolicy(PolicyConfig(denied_tools=frozenset({"denied"})))
    elif mutant is RuntimeSafetyMutant.POLICY_DENIAL_BYPASSED:
        policy = ToolPolicy()
    else:
        policy = ToolPolicy(PolicyConfig(denied_tools=frozenset({"denied"})))
    max_steps = (
        len(scenario.actions) if mutant is RuntimeSafetyMutant.STEP_BUDGET_BYPASSED else scenario.max_steps
    )
    return GovernedAgentRuntime(
        _registry(mutant),
        policy=policy,
        max_steps=max_steps,
    )


def _execute_mutant(mutant: RuntimeSafetyMutant) -> list[ExecutionTrace]:
    traces = []
    for scenario in REVIEWED_SCENARIOS:
        traces.append(
            _runtime(mutant, scenario).execute(
                task=f"mutation-campaign:{scenario.name}",
                plan=list(scenario.actions),
                approved_action_ids=scenario.approved_action_ids,
            )
        )
    return traces


def _detected_boundary(traces: list[ExecutionTrace]) -> SafetyBoundary | None:
    if len(traces) != len(REVIEWED_SCENARIOS):
        raise MutationCampaignError("trace_count_mismatch")
    for probe in reviewed_safety_probes():
        try:
            trace = traces[probe.trace_index]
            result = trace.results[probe.result_index]
        except IndexError:
            return probe.boundary
        if (
            result.status is not probe.expected_status
            or result.policy.decision is not probe.expected_decision
            or trace.stopped_reason != probe.expected_stop_reason
        ):
            return probe.boundary
    return None


def evaluate_runtime_safety_mutants() -> tuple[MutationOutcome, ...]:
    """Run every single-fault variant through the real reviewed runtime suite."""
    outcomes = []
    for mutant in SUPPORTED_MUTANTS:
        detected = _detected_boundary(_execute_mutant(mutant))
        outcomes.append(
            MutationOutcome(
                mutant=mutant,
                expected_boundary=MUTANT_BOUNDARIES[mutant],
                detected_boundary=detected,
                killed=detected is not None,
            )
        )
    return tuple(outcomes)


def _mutation_policy_sha256() -> str:
    document = {
        "mutants": [
            {
                "boundary": MUTANT_BOUNDARIES[mutant].value,
                "mutant": mutant.value,
            }
            for mutant in SUPPORTED_MUTANTS
        ],
        "schema_version": "runtime-safety-mutation-policy/v1",
    }
    return hashlib.sha256(_canonical(document)).hexdigest()


def summarize_mutation_campaign(
    outcomes: tuple[MutationOutcome, ...],
) -> dict[str, object]:
    """Require exact mutant coverage and emit a privacy-reduced receipt."""
    if len(outcomes) != len(SUPPORTED_MUTANTS):
        raise MutationCampaignError("mutation_outcome_count_mismatch")
    by_mutant: dict[RuntimeSafetyMutant, MutationOutcome] = {}
    for outcome in outcomes:
        if outcome.mutant in by_mutant:
            raise MutationCampaignError("duplicate_mutation_outcome")
        by_mutant[outcome.mutant] = outcome
    if set(by_mutant) != set(SUPPORTED_MUTANTS):
        raise MutationCampaignError("mutation_outcome_set_mismatch")
    kill_evidence = []
    for mutant in SUPPORTED_MUTANTS:
        outcome = by_mutant[mutant]
        if not outcome.killed:
            raise MutationCampaignError("mutant_survived")
        if outcome.expected_boundary is not MUTANT_BOUNDARIES[mutant]:
            raise MutationCampaignError("mutant_boundary_mismatch")
        if outcome.detected_boundary is not outcome.expected_boundary:
            raise MutationCampaignError("mutant_killed_by_unexpected_boundary")
        kill_evidence.append(
            {
                "boundary": outcome.detected_boundary.value,
                "mutant": mutant.value,
            }
        )
    kill_evidence_document = {
        "outcomes": kill_evidence,
        "schema_version": "runtime-safety-mutation-kill-evidence/v1",
    }
    document: dict[str, object] = {
        "kill_evidence_sha256": hashlib.sha256(_canonical(kill_evidence_document)).hexdigest(),
        "killed_count": len(outcomes),
        "mutant_count": len(SUPPORTED_MUTANTS),
        "mutation_policy_sha256": _mutation_policy_sha256(),
        "schema_version": MUTATION_CAMPAIGN_SCHEMA,
        "status": "pass",
        "survived_count": 0,
    }
    document["evidence_sha256"] = hashlib.sha256(_canonical(document)).hexdigest()
    return document


def run_runtime_safety_mutation_campaign() -> dict[str, object]:
    return summarize_mutation_campaign(evaluate_runtime_safety_mutants())


def main() -> int:
    print(json.dumps(run_runtime_safety_mutation_campaign(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
