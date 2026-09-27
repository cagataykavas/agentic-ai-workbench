from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from src.governed_runtime import (
    ActionStatus,
    GovernedAgentRuntime,
    PlannedAction,
    PolicyConfig,
    RiskLevel,
    SideEffect,
    ToolPolicy,
    ToolRegistry,
    ToolSpec,
)
from src.plan_binding import (
    PlanBindingError,
    PlanBindingReason,
    ToolContract,
    bind_plan,
    execute_bound_plan,
    verify_plan_binding,
)

NOW = datetime(2026, 9, 28, 0, 0, tzinfo=UTC)
SCHEMA_DIGEST = hashlib.sha256(b'{"type":"object"}').hexdigest()


def build_registry(
    calls: list[dict] | None = None,
    *,
    description: str = "look up one record",
    risk: RiskLevel = RiskLevel.LOW,
    side_effect: SideEffect = SideEffect.NONE,
    idempotent: bool = True,
) -> ToolRegistry:
    def handler(arguments: dict) -> dict:
        if calls is not None:
            calls.append(arguments)
        return {"value": arguments["key"]}

    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            "lookup",
            description,
            handler,
            risk=risk,
            side_effect=side_effect,
            idempotent=idempotent,
        )
    )
    return registry


def contracts(*, version: str = "v1", digest: str = SCHEMA_DIGEST) -> dict[str, ToolContract]:
    return {
        "lookup": ToolContract(
            name="lookup",
            version=version,
            arguments_schema_digest=digest,
        )
    }


def sample_plan(arguments: dict | None = None) -> list[PlannedAction]:
    selected_arguments = {"key": "customer-42"} if arguments is None else arguments
    return [
        PlannedAction(
            "lookup-1",
            "lookup",
            selected_arguments,
            rationale="resolve the requested record",
            idempotency_key="request-42",
        )
    ]


def binding(
    *,
    task: str = "look up the customer record",
    plan: list[PlannedAction] | None = None,
    registry: ToolRegistry | None = None,
    policy: ToolPolicy | None = None,
    active_contracts: dict[str, ToolContract] | None = None,
):
    return bind_plan(
        task=task,
        plan=sample_plan() if plan is None else plan,
        registry=build_registry() if registry is None else registry,
        policy=ToolPolicy() if policy is None else policy,
        contracts=contracts() if active_contracts is None else active_contracts,
        issued_at=NOW,
        ttl_seconds=300,
    )


def reasons_for(
    receipt,
    *,
    task: str = "look up the customer record",
    plan: list[PlannedAction] | None = None,
    registry: ToolRegistry | None = None,
    policy: ToolPolicy | None = None,
    active_contracts: dict[str, ToolContract] | None = None,
    now: datetime = NOW,
) -> tuple[PlanBindingReason, ...]:
    return verify_plan_binding(
        receipt,
        task=task,
        plan=sample_plan() if plan is None else plan,
        registry=build_registry() if registry is None else registry,
        policy=ToolPolicy() if policy is None else policy,
        contracts=contracts() if active_contracts is None else active_contracts,
        now=now,
    ).reasons


def test_bound_plan_executes_only_after_exact_context_verification() -> None:
    calls: list[dict] = []
    registry = build_registry(calls)
    policy = ToolPolicy()
    plan = sample_plan()
    receipt = binding(plan=plan, registry=registry, policy=policy)

    trace = execute_bound_plan(
        GovernedAgentRuntime(registry, policy=policy),
        receipt=receipt,
        task="look up the customer record",
        plan=plan,
        contracts=contracts(),
        now=NOW + timedelta(seconds=1),
    )

    assert trace.results[0].status is ActionStatus.SUCCEEDED
    assert calls == [{"key": "customer-42"}]


@pytest.mark.parametrize(
    ("task", "plan"),
    [
        ("different task", sample_plan()),
        ("look up the customer record", sample_plan({"key": "customer-99"})),
        (
            "look up the customer record",
            [replace(sample_plan()[0], rationale="changed rationale")],
        ),
        (
            "look up the customer record",
            [replace(sample_plan()[0], idempotency_key="request-99")],
        ),
    ],
)
def test_task_or_plan_drift_is_rejected(task: str, plan: list[PlannedAction]) -> None:
    receipt = binding()
    assert reasons_for(receipt, task=task, plan=plan) == (PlanBindingReason.TASK_OR_PLAN_CHANGED,)


@pytest.mark.parametrize(
    "registry",
    [
        build_registry(description="changed planner-facing description"),
        build_registry(risk=RiskLevel.MEDIUM),
        build_registry(side_effect=SideEffect.REVERSIBLE),
        build_registry(idempotent=False),
    ],
)
def test_registered_tool_contract_drift_is_rejected(registry: ToolRegistry) -> None:
    assert reasons_for(binding(), registry=registry) == (PlanBindingReason.TOOL_REGISTRY_CHANGED,)


@pytest.mark.parametrize(
    "active_contracts",
    [contracts(version="v2"), contracts(digest=hashlib.sha256(b"new-schema").hexdigest())],
)
def test_explicit_version_or_argument_schema_drift_is_rejected(
    active_contracts: dict[str, ToolContract],
) -> None:
    assert reasons_for(binding(), active_contracts=active_contracts) == (
        PlanBindingReason.TOOL_REGISTRY_CHANGED,
    )


def test_policy_drift_is_rejected() -> None:
    changed = ToolPolicy(PolicyConfig(denied_tools=frozenset({"lookup"})))
    assert reasons_for(binding(), policy=changed) == (PlanBindingReason.POLICY_CHANGED,)


def test_multiple_drift_reasons_are_reported_deterministically() -> None:
    admission = verify_plan_binding(
        binding(),
        task="changed task",
        plan=sample_plan(),
        registry=build_registry(risk=RiskLevel.MEDIUM),
        policy=ToolPolicy(PolicyConfig(denied_tools=frozenset({"lookup"}))),
        contracts=contracts(version="v2"),
        now=NOW + timedelta(seconds=301),
    )
    assert admission.accepted is False
    assert admission.reasons == (
        PlanBindingReason.EXPIRED,
        PlanBindingReason.TASK_OR_PLAN_CHANGED,
        PlanBindingReason.TOOL_REGISTRY_CHANGED,
        PlanBindingReason.POLICY_CHANGED,
    )


def test_expired_and_future_dated_receipts_fail_closed() -> None:
    receipt = binding()
    assert reasons_for(receipt, now=NOW + timedelta(seconds=300)) == (PlanBindingReason.EXPIRED,)
    assert reasons_for(receipt, now=NOW - timedelta(seconds=6)) == (PlanBindingReason.NOT_YET_VALID,)


def test_deserialized_receipt_invariants_are_revalidated() -> None:
    receipt = binding()
    object.__setattr__(receipt, "action_count", 0)

    admission = verify_plan_binding(
        receipt,
        task="look up the customer record",
        plan=sample_plan(),
        registry=build_registry(),
        policy=ToolPolicy(),
        contracts=contracts(),
        now=NOW,
    )

    assert admission.accepted is False
    assert admission.reasons == (PlanBindingReason.INVALID_RECEIPT,)
    assert len(admission.receipt_digest) == 64


def test_rejection_prevents_handler_dispatch() -> None:
    calls: list[dict] = []
    registry = build_registry(calls)
    runtime = GovernedAgentRuntime(registry)
    receipt = binding(registry=registry)

    with pytest.raises(PlanBindingError) as captured:
        execute_bound_plan(
            runtime,
            receipt=receipt,
            task="look up the customer record",
            plan=sample_plan({"key": "tampered"}),
            contracts=contracts(),
            now=NOW,
        )

    assert captured.value.admission.reasons == (PlanBindingReason.TASK_OR_PLAN_CHANGED,)
    assert calls == []


def test_receipt_and_admission_do_not_expose_task_or_arguments() -> None:
    secret = "private-customer-reference"
    receipt = binding(
        task=f"find {secret}",
        plan=sample_plan({"key": secret}),
    )
    admission = verify_plan_binding(
        receipt,
        task=f"find {secret}",
        plan=sample_plan({"key": secret}),
        registry=build_registry(),
        policy=ToolPolicy(),
        contracts=contracts(),
        now=NOW,
    )

    rendered = json.dumps({"receipt": receipt.as_dict(), "admission": admission.as_dict()})
    assert secret not in rendered
    assert admission.accepted is True
    assert admission.reasons == (PlanBindingReason.ADMITTED,)


def test_digest_is_independent_of_argument_key_order() -> None:
    first = binding(plan=sample_plan({"key": "x", "filters": {"a": 1, "b": 2}}))
    second = binding(plan=sample_plan({"filters": {"b": 2, "a": 1}, "key": "x"}))
    assert first.plan_digest == second.plan_digest
    assert first.receipt_digest == second.receipt_digest


def test_contracts_must_exactly_cover_registry() -> None:
    with pytest.raises(ValueError, match="exactly cover"):
        binding(active_contracts={})

    registry = build_registry()
    registry.register(ToolSpec("extra", "extra", lambda _: {"ok": True}))
    with pytest.raises(ValueError, match="exactly cover"):
        binding(registry=registry)


def test_unknown_tool_and_duplicate_action_ids_are_rejected_at_binding() -> None:
    with pytest.raises(ValueError, match="unknown tool"):
        binding(plan=[PlannedAction("a1", "missing", {})])

    duplicate = [
        PlannedAction("same", "lookup", {"key": "a"}),
        PlannedAction("same", "lookup", {"key": "b"}),
    ]
    with pytest.raises(ValueError, match="duplicate action_id"):
        binding(plan=duplicate)


@pytest.mark.parametrize("ttl", [29, 3601])
def test_ttl_is_bounded(ttl: int) -> None:
    with pytest.raises(ValueError, match="between 30 and 3600"):
        bind_plan(
            task="task",
            plan=sample_plan(),
            registry=build_registry(),
            policy=ToolPolicy(),
            contracts=contracts(),
            issued_at=NOW,
            ttl_seconds=ttl,
        )


def test_timezone_naive_issue_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        bind_plan(
            task="task",
            plan=sample_plan(),
            registry=build_registry(),
            policy=ToolPolicy(),
            contracts=contracts(),
            issued_at=NOW.replace(tzinfo=None),
        )


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_non_finite_arguments_are_rejected(value: float) -> None:
    with pytest.raises(ValueError, match="non-finite"):
        binding(plan=sample_plan({"key": "x", "score": value}))


def test_cyclic_arguments_are_rejected() -> None:
    arguments: dict = {"key": "x"}
    arguments["cycle"] = arguments
    with pytest.raises(ValueError, match="cyclic"):
        binding(plan=sample_plan(arguments))


def test_argument_depth_and_byte_budgets_fail_closed() -> None:
    nested: object = "leaf"
    for _ in range(18):
        nested = [nested]
    with pytest.raises(ValueError, match="depth budget"):
        binding(plan=sample_plan({"key": "x", "nested": nested}))

    with pytest.raises(ValueError, match="byte budget"):
        binding(plan=sample_plan({"key": "x" * 140_000}))


def test_action_count_and_identifier_budgets_fail_closed() -> None:
    with pytest.raises(ValueError, match="action count"):
        binding(plan=[])
    with pytest.raises(ValueError, match="action count"):
        binding(plan=[PlannedAction(f"a-{index}", "lookup", {"key": index}) for index in range(129)])
    with pytest.raises(ValueError, match="action_id"):
        binding(plan=[PlannedAction("bad id", "lookup", {"key": "x"})])


def test_approval_set_is_forwarded_only_after_admission() -> None:
    registry = build_registry(risk=RiskLevel.HIGH)
    policy = ToolPolicy()
    plan = sample_plan()
    receipt = binding(plan=plan, registry=registry, policy=policy)

    trace = execute_bound_plan(
        GovernedAgentRuntime(registry, policy=policy),
        receipt=receipt,
        task="look up the customer record",
        plan=plan,
        contracts=contracts(),
        now=NOW,
        approved_action_ids=frozenset({"lookup-1"}),
    )
    assert trace.results[0].status is ActionStatus.SUCCEEDED
