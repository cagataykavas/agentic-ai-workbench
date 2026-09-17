from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ExpectedStep:
    tool: str
    status: str
    output_contains: Mapping[str, Any] | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ExpectedStep:
        tool = value.get("tool")
        status = value.get("status")
        output_contains = value.get("output_contains")
        if not isinstance(tool, str) or not tool:
            raise ValueError("expected step requires a non-empty string tool")
        if not isinstance(status, str) or not status:
            raise ValueError("expected step requires a non-empty string status")
        if output_contains is not None and not isinstance(output_contains, Mapping):
            raise ValueError("output_contains must be an object")
        return cls(tool=tool, status=status, output_contains=output_contains)


@dataclass(frozen=True)
class TrajectoryResult:
    name: str
    passed: bool
    expected_steps: int
    actual_steps: int
    matched_tools: int
    matched_statuses: int
    matched_outputs: int
    assertions: int
    failures: tuple[str, ...]

    @property
    def assertion_rate(self) -> float:
        return self.assertions / max(1, self.expected_steps * 3)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["assertion_rate"] = self.assertion_rate
        return result


@dataclass(frozen=True)
class SuiteResult:
    cases: int
    passed_cases: int
    pass_rate: float
    assertion_rate: float
    results: tuple[TrajectoryResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": self.cases,
            "passed_cases": self.passed_cases,
            "pass_rate": self.pass_rate,
            "assertion_rate": self.assertion_rate,
            "results": [result.to_dict() for result in self.results],
        }


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping):
        return isinstance(actual, Mapping) and all(
            key in actual and _contains(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) >= len(expected) and all(
            _contains(actual[index], value) for index, value in enumerate(expected)
        )
    return actual == expected


def evaluate_trajectory(
    name: str,
    expected: Sequence[ExpectedStep],
    actual_trace: Mapping[str, Any],
) -> TrajectoryResult:
    raw_results = actual_trace.get("results")
    if not isinstance(raw_results, list):
        raise TypeError("actual trace requires a results array")

    failures: list[str] = []
    matched_tools = 0
    matched_statuses = 0
    matched_outputs = 0
    assertions = 0

    if len(raw_results) != len(expected):
        failures.append(f"step count: expected {len(expected)}, got {len(raw_results)}")

    for index, expected_step in enumerate(expected):
        if index >= len(raw_results):
            failures.append(f"step {index}: missing actual action")
            continue
        actual = raw_results[index]
        if not isinstance(actual, Mapping):
            failures.append(f"step {index}: actual action must be an object")
            continue

        if actual.get("tool") == expected_step.tool:
            matched_tools += 1
            assertions += 1
        else:
            failures.append(
                f"step {index} tool: expected {expected_step.tool!r}, got {actual.get('tool')!r}"
            )

        if actual.get("status") == expected_step.status:
            matched_statuses += 1
            assertions += 1
        else:
            failures.append(
                f"step {index} status: expected {expected_step.status!r}, "
                f"got {actual.get('status')!r}"
            )

        if expected_step.output_contains is None or _contains(
            actual.get("output"), expected_step.output_contains
        ):
            matched_outputs += 1
            assertions += 1
        else:
            failures.append(
                f"step {index} output does not contain {dict(expected_step.output_contains)!r}"
            )

    if len(raw_results) > len(expected):
        for index in range(len(expected), len(raw_results)):
            actual = raw_results[index]
            tool = actual.get("tool") if isinstance(actual, Mapping) else None
            failures.append(f"step {index}: unexpected action {tool!r}")

    return TrajectoryResult(
        name=name,
        passed=not failures,
        expected_steps=len(expected),
        actual_steps=len(raw_results),
        matched_tools=matched_tools,
        matched_statuses=matched_statuses,
        matched_outputs=matched_outputs,
        assertions=assertions,
        failures=tuple(failures),
    )


def evaluate_suite(
    cases: Sequence[tuple[str, Sequence[ExpectedStep], Mapping[str, Any]]],
) -> SuiteResult:
    results = tuple(evaluate_trajectory(name, expected, trace) for name, expected, trace in cases)
    passed = sum(result.passed for result in results)
    total_assertions = sum(result.assertions for result in results)
    possible_assertions = sum(result.expected_steps * 3 for result in results)
    return SuiteResult(
        cases=len(results),
        passed_cases=passed,
        pass_rate=passed / len(results) if results else 0.0,
        assertion_rate=total_assertions / possible_assertions if possible_assertions else 0.0,
        results=results,
    )


def load_case(expectation_path: Path, trace_path: Path) -> tuple[str, list[ExpectedStep], dict[str, Any]]:
    expectation = json.loads(expectation_path.read_text(encoding="utf-8"))
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    if not isinstance(expectation, Mapping):
        raise TypeError("expectation file must contain an object")
    name = expectation.get("name", expectation_path.stem)
    steps = expectation.get("steps")
    if not isinstance(name, str) or not name:
        raise ValueError("expectation name must be a non-empty string")
    if not isinstance(steps, list):
        raise TypeError("expectation requires a steps array")
    if not isinstance(trace, dict):
        raise TypeError("trace file must contain an object")
    return name, [ExpectedStep.from_dict(step) for step in steps], trace


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a recorded agent trajectory")
    parser.add_argument("expectation", type=Path, help="JSON file containing name and expected steps")
    parser.add_argument("trace", type=Path, help="JSON execution trace produced by the runtime")
    parser.add_argument("--output", type=Path, help="optional JSON result path")
    args = parser.parse_args()

    result = evaluate_trajectory(*load_case(args.expectation, args.trace))
    rendered = json.dumps(result.to_dict(), indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
