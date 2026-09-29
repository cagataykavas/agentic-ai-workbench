from __future__ import annotations

import asyncio
import math

import pytest

from src.dag_execution import (
    DagActionStatus,
    DependencyAction,
    DependencyExecutor,
    PlanValidationError,
)
from src.governed_runtime import (
    PolicyConfig,
    RiskLevel,
    ToolPolicy,
    ToolRegistry,
    ToolSpec,
)


def run(coroutine):
    return asyncio.run(coroutine)


def registry_with(**handlers) -> ToolRegistry:
    registry = ToolRegistry()
    for name, handler in handlers.items():
        registry.register(ToolSpec(name, name, handler))
    return registry


def test_dependency_order_is_enforced_and_result_order_matches_plan() -> None:
    observed: list[str] = []

    def handler(arguments: dict) -> dict:
        observed.append(arguments["value"])
        return {"value": arguments["value"]}

    executor = DependencyExecutor(registry_with(work=handler))
    plan = [
        DependencyAction("third", "work", {"value": "third"}, ("second",)),
        DependencyAction("first", "work", {"value": "first"}),
        DependencyAction("second", "work", {"value": "second"}, ("first",)),
    ]

    trace = run(executor.execute("ordered work", plan))

    assert observed == ["first", "second", "third"]
    assert [item.action_id for item in trace.results] == ["third", "first", "second"]
    assert all(item.status is DagActionStatus.SUCCEEDED for item in trace.results)


def test_independent_actions_use_bounded_parallelism() -> None:
    active = 0
    peak = 0
    lock = asyncio.Lock()

    async def handler(arguments: dict) -> dict:
        nonlocal active, peak
        async with lock:
            active += 1
            peak = max(peak, active)
        await asyncio.sleep(0.005)
        async with lock:
            active -= 1
        return {"value": arguments["value"]}

    executor = DependencyExecutor(registry_with(work=handler), max_concurrency=3)
    plan = [DependencyAction(f"a{i}", "work", {"value": i}) for i in range(10)]

    trace = run(executor.execute("parallel work", plan))

    assert peak == 3
    assert [item.output["value"] for item in trace.results] == list(range(10))


def test_failure_blocks_descendants_but_not_independent_branch() -> None:
    calls: list[str] = []

    def handler(arguments: dict) -> dict:
        calls.append(arguments["name"])
        if arguments.get("fail"):
            raise RuntimeError("sensitive downstream detail")
        return {"ok": True}

    executor = DependencyExecutor(registry_with(work=handler))
    plan = [
        DependencyAction("root", "work", {"name": "root", "fail": True}),
        DependencyAction("child", "work", {"name": "child"}, ("root",)),
        DependencyAction("grandchild", "work", {"name": "grandchild"}, ("child",)),
        DependencyAction("independent", "work", {"name": "independent"}),
    ]

    trace = run(executor.execute("failure propagation", plan))

    assert calls == ["root", "independent"]
    assert [item.status for item in trace.results] == [
        DagActionStatus.FAILED,
        DagActionStatus.BLOCKED_DEPENDENCY,
        DagActionStatus.BLOCKED_DEPENDENCY,
        DagActionStatus.SUCCEEDED,
    ]
    assert trace.results[0].error_code == "RuntimeError"
    assert "sensitive" not in str(trace.to_dict())


def test_missing_approval_blocks_downstream_side_effect() -> None:
    calls = 0

    def handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(ToolSpec("reviewed", "reviewed", handler, risk=RiskLevel.HIGH))
    executor = DependencyExecutor(registry)
    plan = [
        DependencyAction("approval", "reviewed", {}),
        DependencyAction("after", "reviewed", {}, ("approval",)),
    ]

    waiting = run(executor.execute("approval", plan))

    assert calls == 0
    assert waiting.results[0].status is DagActionStatus.AWAITING_APPROVAL
    assert waiting.results[1].status is DagActionStatus.BLOCKED_DEPENDENCY


def test_approved_dependency_chain_runs() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec("reviewed", "reviewed", lambda args: {"value": args["value"]}, risk=RiskLevel.HIGH)
    )
    executor = DependencyExecutor(registry)
    plan = [
        DependencyAction("first", "reviewed", {"value": 1}),
        DependencyAction("second", "reviewed", {"value": 2}, ("first",)),
    ]

    trace = run(
        executor.execute(
            "approved",
            plan,
            approved_action_ids=frozenset({"first", "second"}),
        )
    )

    assert all(item.status is DagActionStatus.SUCCEEDED for item in trace.results)


def test_denied_action_blocks_dependants() -> None:
    calls = 0

    def handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"ok": True}

    executor = DependencyExecutor(
        registry_with(blocked=handler),
        policy=ToolPolicy(PolicyConfig(denied_tools=frozenset({"blocked"}))),
    )
    plan = [
        DependencyAction("root", "blocked", {}),
        DependencyAction("child", "blocked", {}, ("root",)),
    ]

    trace = run(executor.execute("denied", plan))

    assert calls == 0
    assert trace.results[0].status is DagActionStatus.DENIED
    assert trace.results[1].status is DagActionStatus.BLOCKED_DEPENDENCY


@pytest.mark.parametrize(
    ("plan", "code"),
    [
        ([], "empty_plan"),
        ([DependencyAction("a", "work", {}), DependencyAction("a", "work", {})], "duplicate_action_id"),
        ([DependencyAction("a", "work", {}, ("missing",))], "unknown_dependency"),
        (
            [
                DependencyAction("a", "work", {}, ("b",)),
                DependencyAction("b", "work", {}, ("a",)),
            ],
            "dependency_cycle",
        ),
        ([DependencyAction("a", "unknown", {})], "unknown_tool"),
        ([DependencyAction("a", "work", {"value": math.nan})], "invalid_json_arguments"),
        ([DependencyAction("a", "work", {}, ("a",))], "self_dependency"),
    ],
)
def test_invalid_graph_fails_before_any_handler(plan: list[DependencyAction], code: str) -> None:
    calls = 0

    def handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"ok": True}

    executor = DependencyExecutor(registry_with(work=handler))

    with pytest.raises(PlanValidationError) as caught:
        run(executor.execute("invalid", plan))

    assert caught.value.code == code
    assert calls == 0


def test_duplicate_idempotency_key_is_rejected_before_parallel_dispatch() -> None:
    calls = 0

    def handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"ok": True}

    executor = DependencyExecutor(registry_with(write=handler))
    plan = [
        DependencyAction("a", "write", {"value": 1}, idempotency_key="shared-key"),
        DependencyAction("b", "write", {"value": 2}, idempotency_key="shared-key"),
    ]

    with pytest.raises(PlanValidationError) as caught:
        run(executor.execute("duplicate write", plan))

    assert caught.value.code == "duplicate_idempotency_key"
    assert calls == 0


def test_same_explicit_key_is_scoped_to_each_tool_contract_across_runs() -> None:
    calls: list[str] = []

    def read(_arguments: dict) -> dict:
        calls.append("read")
        return {"source": "read"}

    def write(_arguments: dict) -> dict:
        calls.append("write")
        return {"source": "write"}

    executor = DependencyExecutor(registry_with(read=read, write=write))

    first = run(
        executor.execute(
            "read",
            [DependencyAction("a", "read", {}, idempotency_key="shared-key")],
        )
    )
    second = run(
        executor.execute(
            "write",
            [DependencyAction("b", "write", {}, idempotency_key="shared-key")],
        )
    )

    assert calls == ["read", "write"]
    assert first.results[0].output == {"source": "read"}
    assert second.results[0].output == {"source": "write"}


def test_replay_satisfies_dependency_without_repeating_handler() -> None:
    calls = 0

    def handler(arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"value": arguments["value"]}

    executor = DependencyExecutor(registry_with(work=handler))
    plan = [
        DependencyAction("root", "work", {"value": 1}, idempotency_key="root-key"),
        DependencyAction("child", "work", {"value": 2}, ("root",), "child-key"),
    ]

    first = run(executor.execute("first", plan))
    second = run(executor.execute("retry", plan))

    assert calls == 2
    assert all(item.status is DagActionStatus.SUCCEEDED for item in first.results)
    assert all(item.status is DagActionStatus.REPLAYED for item in second.results)


def test_validator_failure_blocks_handler_and_dependant() -> None:
    calls = 0

    def validator(_arguments: dict) -> None:
        raise ValueError("invalid")

    def handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"ok": True}

    registry = ToolRegistry()
    registry.register(ToolSpec("work", "work", handler, validator=validator))
    executor = DependencyExecutor(registry)
    plan = [
        DependencyAction("root", "work", {}),
        DependencyAction("child", "work", {}, ("root",)),
    ]

    trace = run(executor.execute("validation", plan))

    assert calls == 0
    assert trace.results[0].status is DagActionStatus.FAILED
    assert trace.results[1].status is DagActionStatus.BLOCKED_DEPENDENCY


def test_output_contract_failure_is_bounded() -> None:
    executor = DependencyExecutor(registry_with(work=lambda _args: "not-an-object"))

    trace = run(executor.execute("bad output", [DependencyAction("a", "work", {})]))

    assert trace.results[0].status is DagActionStatus.FAILED
    assert trace.results[0].error_code == "TypeError"
    assert trace.results[0].output is None


def test_plan_digest_is_stable_across_argument_key_order() -> None:
    executor = DependencyExecutor(registry_with(work=lambda args: args))
    left = [DependencyAction("a", "work", {"x": 1, "y": 2})]
    right = [DependencyAction("a", "work", {"y": 2, "x": 1})]

    first = run(executor.execute("same", left))
    second = run(executor.execute("same", right))

    assert first.plan_sha256 == second.plan_sha256
    assert first.task_sha256 == second.task_sha256
    assert "same" not in str(first.to_dict())


def test_action_budget_fails_before_dispatch() -> None:
    calls = 0

    def handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"ok": True}

    executor = DependencyExecutor(registry_with(work=handler), max_actions=2)
    plan = [DependencyAction(f"a{i}", "work", {}) for i in range(3)]

    with pytest.raises(PlanValidationError) as caught:
        run(executor.execute("too large", plan))

    assert caught.value.code == "action_budget_exceeded"
    assert calls == 0


def test_unknown_approval_fails_before_dispatch() -> None:
    calls = 0

    def handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"ok": True}

    executor = DependencyExecutor(registry_with(work=handler))

    with pytest.raises(PlanValidationError) as caught:
        run(
            executor.execute(
                "approval drift",
                [DependencyAction("a", "work", {})],
                approved_action_ids=frozenset({"old-action"}),
            )
        )

    assert caught.value.code == "unknown_approval"
    assert calls == 0


def test_unexpected_handler_exception_isolated_from_independent_action() -> None:
    def handler(arguments: dict) -> dict:
        if arguments["name"] == "broken":
            raise KeyError("private key")
        return {"ok": True}

    executor = DependencyExecutor(registry_with(work=handler))
    plan = [
        DependencyAction("broken", "work", {"name": "broken"}),
        DependencyAction("healthy", "work", {"name": "healthy"}),
    ]

    trace = run(executor.execute("isolate", plan))

    assert trace.results[0].status is DagActionStatus.FAILED
    assert trace.results[0].error_code == "KeyError"
    assert trace.results[1].status is DagActionStatus.SUCCEEDED
    assert "private key" not in str(trace.to_dict())


def test_cancellation_waits_for_active_wave_to_reach_terminal_state() -> None:
    async def scenario() -> tuple[bool, bool]:
        started = asyncio.Event()
        release = asyncio.Event()
        completed = False

        async def handler(_arguments: dict) -> dict:
            nonlocal completed
            started.set()
            await release.wait()
            completed = True
            return {"ok": True}

        executor = DependencyExecutor(registry_with(work=handler))
        execution = asyncio.create_task(executor.execute("cancel", [DependencyAction("a", "work", {})]))
        await started.wait()
        execution.cancel()
        await asyncio.sleep(0)
        was_pending = not execution.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await execution
        return was_pending, completed

    assert run(scenario()) == (True, True)
