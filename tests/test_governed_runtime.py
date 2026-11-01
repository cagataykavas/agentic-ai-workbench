from src.governed_runtime import (
    ActionStatus,
    ExecutionLedger,
    GovernedAgentRuntime,
    PlannedAction,
    PolicyConfig,
    RiskLevel,
    SideEffect,
    ToolPolicy,
    ToolRegistry,
    ToolSpec,
)
from src.runtime_eval import evaluate_trace


def test_low_risk_read_only_tool_runs_automatically():
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="lookup",
            description="read a public record",
            handler=lambda args: {"value": args["key"]},
        )
    )
    runtime = GovernedAgentRuntime(registry)
    trace = runtime.execute(
        "look up record",
        [PlannedAction("a1", "lookup", {"key": "demo"})],
    )
    assert trace.results[0].status is ActionStatus.SUCCEEDED
    assert trace.results[0].output == {"value": "demo"}


def test_high_risk_tool_waits_for_explicit_approval():
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="publish",
            description="publish an external change",
            handler=lambda args: {"published": args["item"]},
            risk=RiskLevel.HIGH,
            side_effect=SideEffect.IRREVERSIBLE,
        )
    )
    runtime = GovernedAgentRuntime(registry)
    plan = [PlannedAction("publish-1", "publish", {"item": "release"})]

    waiting = runtime.execute("publish release", plan)
    assert waiting.results[0].status is ActionStatus.AWAITING_APPROVAL

    approved = runtime.execute(
        "publish release",
        plan,
        approved_action_ids=frozenset({"publish-1"}),
    )
    assert approved.results[0].status is ActionStatus.SUCCEEDED


def test_idempotency_ledger_replays_duplicate_success_without_second_side_effect():
    calls = {"count": 0}

    def handler(args: dict) -> dict:
        calls["count"] += 1
        return {"saved": args["value"]}

    registry = ToolRegistry()
    registry.register(ToolSpec("save", "save record", handler, side_effect=SideEffect.REVERSIBLE))
    runtime = GovernedAgentRuntime(registry)
    action = PlannedAction("save-1", "save", {"value": 7}, idempotency_key="request-123")

    first = runtime.execute("save", [action])
    second = runtime.execute("save retry", [action])
    assert first.results[0].status is ActionStatus.SUCCEEDED
    assert second.results[0].status is ActionStatus.REPLAYED
    assert calls["count"] == 1


def test_explicit_idempotency_key_rejects_changed_request_before_dispatch():
    calls: list[int] = []

    def handler(args: dict) -> dict:
        calls.append(args["value"])
        return {"saved": args["value"]}

    registry = ToolRegistry()
    registry.register(ToolSpec("save", "save record", handler))
    runtime = GovernedAgentRuntime(registry)

    original = runtime.execute(
        "save original",
        [PlannedAction("first", "save", {"value": 7}, idempotency_key="request-123")],
    )
    changed = runtime.execute(
        "save changed",
        [PlannedAction("second", "save", {"value": 8}, idempotency_key="request-123")],
    )

    assert original.results[0].status is ActionStatus.SUCCEEDED
    assert changed.results[0].status is ActionStatus.FAILED
    assert changed.results[0].error == "idempotency_key_payload_mismatch"
    assert changed.results[0].output is None
    assert calls == [7]


def test_canonical_request_digest_replays_equivalent_argument_order():
    calls = 0

    def handler(args: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"total": args["left"] + args["right"]}

    registry = ToolRegistry()
    registry.register(ToolSpec("add", "add values", handler))
    runtime = GovernedAgentRuntime(registry)

    first = runtime.execute(
        "add",
        [
            PlannedAction(
                "first",
                "add",
                {"left": 2, "right": 3},
                idempotency_key="addition-1",
            )
        ],
    )
    reordered = runtime.execute(
        "add retry",
        [
            PlannedAction(
                "second",
                "add",
                {"right": 3, "left": 2},
                idempotency_key="addition-1",
            )
        ],
    )

    assert first.results[0].status is ActionStatus.SUCCEEDED
    assert reordered.results[0].status is ActionStatus.REPLAYED
    assert reordered.results[0].output == {"total": 5}
    assert calls == 1


def test_legacy_key_only_entry_fails_closed_without_dispatch():
    ledger = ExecutionLedger()
    ledger.record("request-123", {"saved": "legacy"})
    calls = 0

    def handler(args: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"saved": args["value"]}

    registry = ToolRegistry()
    registry.register(ToolSpec("save", "save record", handler))
    result = GovernedAgentRuntime(registry, ledger=ledger).execute(
        "retry legacy request",
        [PlannedAction("retry", "save", {"value": 7}, idempotency_key="request-123")],
    )

    assert result.results[0].status is ActionStatus.FAILED
    assert result.results[0].error == "idempotency_key_payload_mismatch"
    assert calls == 0


def test_policy_can_deny_registered_tool():
    registry = ToolRegistry()
    registry.register(ToolSpec("blocked", "blocked tool", lambda _args: {"ok": True}))
    runtime = GovernedAgentRuntime(
        registry,
        policy=ToolPolicy(PolicyConfig(denied_tools=frozenset({"blocked"}))),
    )
    trace = runtime.execute("try blocked", [PlannedAction("b1", "blocked", {})])
    assert trace.results[0].status is ActionStatus.DENIED


def test_step_budget_marks_remaining_actions_without_executing_them():
    registry = ToolRegistry()
    registry.register(ToolSpec("read", "read", lambda args: {"value": args["value"]}))
    runtime = GovernedAgentRuntime(registry, max_steps=1)
    trace = runtime.execute(
        "two reads",
        [
            PlannedAction("r1", "read", {"value": 1}),
            PlannedAction("r2", "read", {"value": 2}),
        ],
    )
    assert trace.results[0].status is ActionStatus.SUCCEEDED
    assert trace.results[1].status is ActionStatus.SKIPPED_BUDGET
    assert trace.stopped_reason == "step_budget_exhausted"


def test_runtime_metrics_expose_governance_outcomes():
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            "reviewed",
            "needs human review",
            lambda _args: {"ok": True},
            risk=RiskLevel.HIGH,
        )
    )
    trace = GovernedAgentRuntime(registry).execute(
        "review action",
        [PlannedAction("x", "reviewed", {})],
    )
    metrics = evaluate_trace(trace)
    assert metrics.approval_rate == 1.0
    assert metrics.success_rate == 0.0
