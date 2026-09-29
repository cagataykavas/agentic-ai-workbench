from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from collections.abc import Awaitable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, cast

from src.governed_runtime import (
    Decision,
    ExecutionLedger,
    PolicyResult,
    ToolPolicy,
    ToolRegistry,
    ToolSpec,
)

MAX_ARGUMENT_BYTES = 65_536
MAX_ACTIONS_HARD_LIMIT = 256
MAX_DEPENDENCIES_PER_ACTION = 32
MAX_TOTAL_DEPENDENCIES = 2_048
MAX_CONCURRENCY_HARD_LIMIT = 64
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class PlanValidationError(ValueError):
    """A plan is structurally unsafe and no tool handler was started."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DagActionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    REPLAYED = "replayed"
    FAILED = "failed"
    DENIED = "denied"
    AWAITING_APPROVAL = "awaiting_approval"
    BLOCKED_DEPENDENCY = "blocked_dependency"


@dataclass(frozen=True, slots=True)
class DependencyAction:
    action_id: str
    tool: str
    arguments: dict[str, Any]
    depends_on: tuple[str, ...] = ()
    idempotency_key: str | None = None


@dataclass(frozen=True, slots=True)
class DagActionResult:
    action_id: str
    tool: str
    status: DagActionStatus
    output: dict[str, Any] | None
    error_code: str | None
    policy: PolicyResult
    idempotency_key_sha256: str

    @property
    def satisfies_dependency(self) -> bool:
        return self.status in {DagActionStatus.SUCCEEDED, DagActionStatus.REPLAYED}


@dataclass(slots=True)
class DagExecutionTrace:
    task_sha256: str
    plan_sha256: str
    planned_actions: int
    max_concurrency: int
    results: list[DagActionResult] = field(default_factory=list)
    stopped_reason: str = "plan_completed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_sha256": self.task_sha256,
            "plan_sha256": self.plan_sha256,
            "planned_actions": self.planned_actions,
            "max_concurrency": self.max_concurrency,
            "stopped_reason": self.stopped_reason,
            "results": [
                {
                    **asdict(result),
                    "status": result.status.value,
                    "policy": {
                        "decision": result.policy.decision.value,
                        "reason": result.policy.reason,
                    },
                }
                for result in self.results
            ],
        }


@dataclass(frozen=True, slots=True)
class _PreparedAction:
    action_id: str
    tool: ToolSpec
    arguments: dict[str, Any]
    depends_on: tuple[str, ...]
    idempotency_key: str


def _canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PlanValidationError("invalid_json_arguments") from exc
    if len(encoded) > MAX_ARGUMENT_BYTES:
        raise PlanValidationError("argument_budget_exceeded")
    return encoded


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_identifier(value: str, code: str) -> None:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise PlanValidationError(code)


class DependencyExecutor:
    """Execute a validated tool-call DAG with bounded parallelism.

    The complete graph is checked before any handler starts. Successful or
    replayed parents unlock dependants; every other terminal parent state blocks
    the dependant without invoking its tool.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        policy: ToolPolicy | None = None,
        ledger: ExecutionLedger | None = None,
        max_actions: int = 128,
        max_concurrency: int = 8,
    ) -> None:
        if not 1 <= max_actions <= MAX_ACTIONS_HARD_LIMIT:
            raise ValueError("max_actions is outside the supported range")
        if not 1 <= max_concurrency <= MAX_CONCURRENCY_HARD_LIMIT:
            raise ValueError("max_concurrency is outside the supported range")
        self.registry = registry
        self.policy = policy or ToolPolicy()
        self.ledger = ledger or ExecutionLedger()
        self.max_actions = max_actions
        self.max_concurrency = max_concurrency

    def _prepare(self, plan: list[DependencyAction]) -> tuple[list[_PreparedAction], str]:
        if not plan:
            raise PlanValidationError("empty_plan")
        if len(plan) > self.max_actions:
            raise PlanValidationError("action_budget_exceeded")

        action_ids: set[str] = set()
        for action in plan:
            _validate_identifier(action.action_id, "invalid_action_id")
            _validate_identifier(action.tool, "invalid_tool_name")
            if action.action_id in action_ids:
                raise PlanValidationError("duplicate_action_id")
            action_ids.add(action.action_id)

        prepared: list[_PreparedAction] = []
        idempotency_owners: dict[str, list[_PreparedAction]] = {}
        edge_count = 0
        for action in plan:
            if len(action.depends_on) > MAX_DEPENDENCIES_PER_ACTION:
                raise PlanValidationError("dependency_fan_in_exceeded")
            if len(set(action.depends_on)) != len(action.depends_on):
                raise PlanValidationError("duplicate_dependency")
            edge_count += len(action.depends_on)
            if edge_count > MAX_TOTAL_DEPENDENCIES:
                raise PlanValidationError("dependency_budget_exceeded")
            for dependency in action.depends_on:
                _validate_identifier(dependency, "invalid_dependency_id")
                if dependency == action.action_id:
                    raise PlanValidationError("self_dependency")
                if dependency not in action_ids:
                    raise PlanValidationError("unknown_dependency")

            try:
                tool = self.registry.get(action.tool)
            except KeyError as exc:
                raise PlanValidationError("unknown_tool") from exc

            argument_bytes = _canonical_json(action.arguments)
            arguments = cast(dict[str, Any], json.loads(argument_bytes))
            if not isinstance(arguments, dict):
                raise PlanValidationError("arguments_not_object")
            if action.idempotency_key is not None:
                _validate_identifier(action.idempotency_key, "invalid_idempotency_key")
                raw_key = action.idempotency_key
            else:
                raw_key = _sha256(_canonical_json({"tool": action.tool, "arguments": arguments}))
            key = f"{action.tool}:{raw_key}"
            candidate = _PreparedAction(
                action_id=action.action_id,
                tool=tool,
                arguments=arguments,
                depends_on=action.depends_on,
                idempotency_key=key,
            )
            prepared.append(candidate)
            if tool.idempotent:
                idempotency_owners.setdefault(key, []).append(candidate)

        indegree = {action.action_id: len(action.depends_on) for action in prepared}
        children: dict[str, list[str]] = {action.action_id: [] for action in prepared}
        for action in prepared:
            for dependency in action.depends_on:
                children[dependency].append(action.action_id)
        ready = [action.action_id for action in prepared if indegree[action.action_id] == 0]
        visited = 0
        while ready:
            current = ready.pop()
            visited += 1
            for child in children[current]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    ready.append(child)
        if visited != len(prepared):
            raise PlanValidationError("dependency_cycle")

        def reaches(source: str, target: str) -> bool:
            frontier = list(children[source])
            seen: set[str] = set()
            while frontier:
                current = frontier.pop()
                if current == target:
                    return True
                if current not in seen:
                    seen.add(current)
                    frontier.extend(children[current])
            return False

        for owners in idempotency_owners.values():
            if len(owners) < 2:
                continue
            for left_index, left in enumerate(owners):
                for right in owners[left_index + 1 :]:
                    if not (
                        reaches(left.action_id, right.action_id) or reaches(right.action_id, left.action_id)
                    ):
                        raise PlanValidationError("duplicate_idempotency_key")

        plan_projection = [
            {
                "action_id": action.action_id,
                "tool": action.tool.name,
                "arguments": action.arguments,
                "depends_on": list(action.depends_on),
                "idempotency_key_sha256": _sha256(action.idempotency_key.encode()),
            }
            for action in prepared
        ]
        return prepared, _sha256(_canonical_json(plan_projection))

    async def _call_handler(self, action: _PreparedAction) -> dict[str, Any]:
        handler = action.tool.handler
        if inspect.iscoroutinefunction(handler):
            value = await cast(Awaitable[Any], handler(dict(action.arguments)))
        else:
            value = await asyncio.to_thread(handler, dict(action.arguments))
            if inspect.isawaitable(value):
                value = await cast(Awaitable[Any], value)
        if not isinstance(value, dict):
            raise TypeError("tool_output_not_object")
        output_bytes = _canonical_json(value)
        return cast(dict[str, Any], json.loads(output_bytes))

    async def _run_action(
        self,
        action: _PreparedAction,
        approved_action_ids: frozenset[str],
    ) -> DagActionResult:
        policy_result = self.policy.evaluate(action.tool)
        key_digest = _sha256(action.idempotency_key.encode())
        if policy_result.decision is Decision.DENY:
            return DagActionResult(
                action.action_id,
                action.tool.name,
                DagActionStatus.DENIED,
                None,
                None,
                policy_result,
                key_digest,
            )
        if (
            policy_result.decision is Decision.REQUIRE_APPROVAL
            and action.action_id not in approved_action_ids
        ):
            return DagActionResult(
                action.action_id,
                action.tool.name,
                DagActionStatus.AWAITING_APPROVAL,
                None,
                None,
                policy_result,
                key_digest,
            )

        cached = self.ledger.get(action.idempotency_key) if action.tool.idempotent else None
        if cached is not None:
            return DagActionResult(
                action.action_id,
                action.tool.name,
                DagActionStatus.REPLAYED,
                cached,
                None,
                policy_result,
                key_digest,
            )
        try:
            if action.tool.validator:
                action.tool.validator(dict(action.arguments))
            output = await self._call_handler(action)
        except Exception as exc:  # noqa: BLE001 - a tool boundary must isolate handler failures.
            return DagActionResult(
                action.action_id,
                action.tool.name,
                DagActionStatus.FAILED,
                None,
                type(exc).__name__,
                policy_result,
                key_digest,
            )
        if action.tool.idempotent:
            self.ledger.record(action.idempotency_key, output)
        return DagActionResult(
            action.action_id,
            action.tool.name,
            DagActionStatus.SUCCEEDED,
            output,
            None,
            policy_result,
            key_digest,
        )

    async def execute(
        self,
        task: str,
        plan: list[DependencyAction],
        *,
        approved_action_ids: frozenset[str] = frozenset(),
    ) -> DagExecutionTrace:
        if not isinstance(task, str) or not task:
            raise PlanValidationError("invalid_task")
        try:
            task_bytes = task.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PlanValidationError("invalid_task") from exc
        if len(task_bytes) > 65_536:
            raise PlanValidationError("invalid_task")
        prepared, plan_digest = self._prepare(plan)
        action_ids = {action.action_id for action in prepared}
        if not approved_action_ids.issubset(action_ids):
            raise PlanValidationError("unknown_approval")
        task_digest = _sha256(task_bytes)
        by_id = {action.action_id: action for action in prepared}
        index = {action.action_id: position for position, action in enumerate(prepared)}
        results: dict[str, DagActionResult] = {}
        pending = set(by_id)

        while pending:
            ready = sorted(
                (
                    action_id
                    for action_id in pending
                    if all(dependency in results for dependency in by_id[action_id].depends_on)
                ),
                key=index.__getitem__,
            )
            if not ready:
                raise RuntimeError("validated dependency graph made no progress")

            runnable: list[_PreparedAction] = []
            for action_id in ready:
                action = by_id[action_id]
                failed_dependencies = [
                    dependency
                    for dependency in action.depends_on
                    if not results[dependency].satisfies_dependency
                ]
                if failed_dependencies:
                    results[action_id] = DagActionResult(
                        action.action_id,
                        action.tool.name,
                        DagActionStatus.BLOCKED_DEPENDENCY,
                        None,
                        "dependency_not_satisfied",
                        PolicyResult(Decision.DENY, "one or more dependencies did not succeed"),
                        _sha256(action.idempotency_key.encode()),
                    )
                    pending.remove(action_id)
                else:
                    runnable.append(action)

            for start in range(0, len(runnable), self.max_concurrency):
                batch = runnable[start : start + self.max_concurrency]
                running = asyncio.gather(*(self._run_action(action, approved_action_ids) for action in batch))
                try:
                    batch_results = await asyncio.shield(running)
                except asyncio.CancelledError:
                    await asyncio.shield(running)
                    raise
                for result in batch_results:
                    results[result.action_id] = result
                    pending.remove(result.action_id)

        ordered_results = [results[action.action_id] for action in prepared]
        stopped_reason = (
            "plan_completed"
            if all(result.satisfies_dependency for result in ordered_results)
            else "plan_completed_with_blocked_or_failed_actions"
        )
        return DagExecutionTrace(
            task_sha256=task_digest,
            plan_sha256=plan_digest,
            planned_actions=len(prepared),
            max_concurrency=self.max_concurrency,
            results=ordered_results,
            stopped_reason=stopped_reason,
        )
