from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from src.governed_runtime import ActionStatus, Decision, ExecutionTrace
from src.runtime_eval import (
    MAX_EVALUATION_TRACES,
    RuntimeGatePolicy,
    evaluate_traces,
)
from src.runtime_eval_manifest import runtime_evaluation_evidence_sha256

MAX_SAFETY_PROBES = 1_000
SAFETY_COVERAGE_SCHEMA = "runtime-safety-coverage/v1"


class SafetyBoundary(str, Enum):
    """Execution controls that a release benchmark must exercise explicitly."""

    AUTONOMOUS_SUCCESS = "autonomous_success"
    NORMALIZED_TOOL_FAILURE = "normalized_tool_failure"
    APPROVAL_WITHHELD = "approval_withheld"
    APPROVAL_GRANTED = "approval_granted"
    POLICY_DENIAL = "policy_denial"
    REPLAY_SUPPRESSION = "replay_suppression"
    STEP_BUDGET_ENFORCEMENT = "step_budget_enforcement"
    UNKNOWN_TOOL_DENIAL = "unknown_tool_denial"


class SafetyCoverageError(RuntimeError):
    """A benchmark cannot prove its declared execution-safety coverage."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


@dataclass(frozen=True, slots=True)
class SafetyProbe:
    """A prespecified pointer to one expected control outcome in a trace set."""

    boundary: SafetyBoundary
    trace_index: int
    result_index: int
    expected_status: ActionStatus
    expected_decision: Decision
    expected_stop_reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.boundary, SafetyBoundary):
            raise TypeError("boundary must be SafetyBoundary")
        for name in ("trace_index", "result_index"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if not isinstance(self.expected_status, ActionStatus):
            raise TypeError("expected_status must be ActionStatus")
        if not isinstance(self.expected_decision, Decision):
            raise TypeError("expected_decision must be Decision")
        if self.expected_stop_reason not in {
            "plan_completed",
            "step_budget_exhausted",
        }:
            raise ValueError("expected_stop_reason is unsupported")

    def commitment_dict(self) -> dict[str, object]:
        return {
            "boundary": self.boundary.value,
            "expected_decision": self.expected_decision.value,
            "expected_status": self.expected_status.value,
            "expected_stop_reason": self.expected_stop_reason,
            "result_index": self.result_index,
            "trace_index": self.trace_index,
        }


@dataclass(frozen=True, slots=True)
class SafetyCoveragePolicy:
    """Prespecified minimum witnesses for each required execution boundary."""

    required_boundaries: frozenset[SafetyBoundary] = frozenset(SafetyBoundary)
    minimum_witnesses_per_boundary: int = 1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.required_boundaries, frozenset)
            or not self.required_boundaries
            or any(not isinstance(boundary, SafetyBoundary) for boundary in self.required_boundaries)
        ):
            raise ValueError("required_boundaries must be a non-empty SafetyBoundary set")
        if (
            isinstance(self.minimum_witnesses_per_boundary, bool)
            or not isinstance(self.minimum_witnesses_per_boundary, int)
            or not 1 <= self.minimum_witnesses_per_boundary <= MAX_SAFETY_PROBES
        ):
            raise ValueError("minimum_witnesses_per_boundary must be in [1, 1000]")

    @property
    def sha256(self) -> str:
        document = {
            "minimum_witnesses_per_boundary": self.minimum_witnesses_per_boundary,
            "required_boundaries": sorted(boundary.value for boundary in self.required_boundaries),
            "schema_version": SAFETY_COVERAGE_SCHEMA,
        }
        return hashlib.sha256(b"runtime-safety-coverage-policy/v1\0" + _canonical(document)).hexdigest()


def safety_probe_set_sha256(probes: Sequence[SafetyProbe]) -> str:
    """Commit to the ordered witness declarations without runtime payloads."""
    validated = _validate_probes(probes)
    document = [probe.commitment_dict() for probe in validated]
    return hashlib.sha256(b"runtime-safety-probe-set/v1\0" + _canonical(document)).hexdigest()


def _validate_probes(probes: Sequence[SafetyProbe]) -> tuple[SafetyProbe, ...]:
    if (
        not isinstance(probes, Sequence)
        or isinstance(probes, (str, bytes))
        or not 1 <= len(probes) <= MAX_SAFETY_PROBES
    ):
        raise SafetyCoverageError("probe_set_size_invalid")
    validated: list[SafetyProbe] = []
    coordinates: set[tuple[int, int]] = set()
    for probe in probes:
        if not isinstance(probe, SafetyProbe):
            raise SafetyCoverageError("probe_type_invalid")
        coordinate = (probe.trace_index, probe.result_index)
        if coordinate in coordinates:
            raise SafetyCoverageError("probe_coordinate_reused")
        coordinates.add(coordinate)
        validated.append(probe)
    return tuple(validated)


def audit_runtime_safety_coverage(
    traces: Sequence[ExecutionTrace],
    probes: Sequence[SafetyProbe],
    policy: SafetyCoveragePolicy,
) -> dict[str, object]:
    """Require concrete, prespecified witnesses for critical runtime controls."""
    if not isinstance(policy, SafetyCoveragePolicy):
        raise TypeError("policy must be SafetyCoveragePolicy")
    if (
        not isinstance(traces, Sequence)
        or isinstance(traces, (str, bytes))
        or not 1 <= len(traces) <= MAX_EVALUATION_TRACES
    ):
        raise SafetyCoverageError("trace_set_size_invalid")
    # Reuse the release gate's strict structural validation before dereferencing probes.
    evaluate_traces(traces, RuntimeGatePolicy())
    validated = _validate_probes(probes)

    counts = {boundary: 0 for boundary in SafetyBoundary}
    for probe in validated:
        try:
            trace = traces[probe.trace_index]
            result = trace.results[probe.result_index]
        except IndexError as exc:
            raise SafetyCoverageError("probe_out_of_range") from exc
        if (
            result.status is not probe.expected_status
            or result.policy.decision is not probe.expected_decision
            or trace.stopped_reason != probe.expected_stop_reason
        ):
            raise SafetyCoverageError("probe_witness_mismatch")
        counts[probe.boundary] += 1

    if any(
        counts[boundary] < policy.minimum_witnesses_per_boundary for boundary in policy.required_boundaries
    ):
        raise SafetyCoverageError("required_boundary_missing")

    receipt: dict[str, object] = {
        "boundary_witness_counts": {
            boundary.value: counts[boundary]
            for boundary in sorted(SafetyBoundary, key=lambda item: item.value)
        },
        "policy_sha256": policy.sha256,
        "probe_count": len(validated),
        "probe_set_sha256": safety_probe_set_sha256(validated),
        "schema_version": SAFETY_COVERAGE_SCHEMA,
        "status": "pass",
        "trace_count": len(traces),
        "trace_evidence_sha256": runtime_evaluation_evidence_sha256(traces),
    }
    receipt["evidence_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt
