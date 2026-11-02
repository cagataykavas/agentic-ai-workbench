from __future__ import annotations

import math

import pytest

from src.dag_execution import DependencyAction, DependencyExecutor
from src.governed_runtime import GovernedAgentRuntime, PlannedAction, ToolRegistry, ToolSpec
from src.request_identity import CanonicalRequestError, CanonicalRequestIdentity


def registry() -> ToolRegistry:
    tools = ToolRegistry()
    tools.register(ToolSpec("write", "write", lambda arguments: dict(arguments)))
    return tools


def test_identity_is_order_independent_and_detached_from_caller_mutation() -> None:
    arguments = {"nested": {"right": 2, "left": 1}, "items": [3, 4]}
    first = CanonicalRequestIdentity.from_parts("write", arguments)
    reordered = CanonicalRequestIdentity.from_parts(
        "write",
        {"items": [3, 4], "nested": {"left": 1, "right": 2}},
    )

    arguments["nested"]["left"] = 99

    assert first.sha256 == reordered.sha256
    assert first.arguments == {
        "items": [3, 4],
        "nested": {"left": 1, "right": 2},
    }


def test_basic_and_dependency_paths_use_the_same_request_identity() -> None:
    arguments = {"value": 7, "metadata": {"b": 2, "a": 1}}
    expected = CanonicalRequestIdentity.from_parts("write", arguments)

    basic_digest = GovernedAgentRuntime._request_sha256(PlannedAction("basic", "write", arguments))
    prepared, _ = DependencyExecutor(registry())._prepare(
        [DependencyAction("dependency", "write", arguments)]
    )

    assert basic_digest == expected.sha256
    assert prepared[0].request_sha256 == expected.sha256
    assert prepared[0].arguments == expected.arguments


@pytest.mark.parametrize(
    "arguments",
    [
        {"value": math.nan},
        {"value": math.inf},
        {"value": {1, 2}},
        ["not", "an", "object"],
    ],
)
def test_rejects_noncanonical_or_nonobject_arguments(arguments: object) -> None:
    with pytest.raises(CanonicalRequestError) as captured:
        CanonicalRequestIdentity.from_parts("write", arguments)
    expected = "arguments_not_object" if isinstance(arguments, list) else "invalid_json_arguments"
    assert captured.value.code == expected


def test_rejects_oversized_requests_and_invalid_limits() -> None:
    with pytest.raises(CanonicalRequestError) as captured:
        CanonicalRequestIdentity.from_parts(
            "write",
            {"value": "x" * 1_000},
            max_bytes=256,
        )
    assert captured.value.code == "argument_budget_exceeded"

    with pytest.raises(ValueError, match="max_bytes"):
        CanonicalRequestIdentity.from_parts("write", {}, max_bytes=True)
