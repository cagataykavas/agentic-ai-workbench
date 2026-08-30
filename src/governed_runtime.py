from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SideEffect(str, Enum):
    NONE = "none"
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ActionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    AWAITING_APPROVAL = "awaiting_approval"
    REPLAYED = "replayed"
    SKIPPED_BUDGET = "skipped_budget"


Payload = dict[str, Any]
ToolHandler = Callable[[Payload], Payload]
Validator = Callable[[Payload], None]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    handler: ToolHandler
    risk: RiskLevel = RiskLevel.LOW
    side_effect: SideEffect = SideEffect.NONE
    idempotent: bool = True
    validator: Validator | None = None


@dataclass(frozen=True)
class PlannedAction:
    action_id: str
    tool: str
    arguments: Payload
    rationale: str = ""
    idempotency_key: str | None = None


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str


@dataclass(frozen=True)
class ActionResult:
    action_id: str
    tool: str
    status: ActionStatus
    output: Payload | None
    error: str | None
    policy: PolicyResult
    idempotency_key: str


@dataclass
class ExecutionTrace:
    task: str
    planned_actions: int
    max_steps: int
    results: list[ActionResult] = field(default_factory=list)
    stopped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "planned_actions": self.planned_actions,
            "max_steps": self.max_steps,
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


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {name}") from exc

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))


@dataclass(frozen=True)
class PolicyConfig:
    denied_tools: frozenset[str] = frozenset()
    require_approval_for_medium_risk: bool = False
    require_approval_for_reversible_side_effects: bool = False


class ToolPolicy:
    """Make execution authority explicit and independent from the planner.

    A planner may *propose* any registered action. This policy decides whether
    the runtime is allowed to execute it without human approval.
    """

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    def evaluate(self, tool: ToolSpec) -> PolicyResult:
        if tool.name in self.config.denied_tools:
            return PolicyResult(Decision.DENY, "tool is explicitly denied by policy")
        if tool.risk is RiskLevel.HIGH:
            return PolicyResult(Decision.REQUIRE_APPROVAL, "high-risk tool requires approval")
        if tool.side_effect is SideEffect.IRREVERSIBLE:
            return PolicyResult(
                Decision.REQUIRE_APPROVAL,
                "irreversible side effect requires approval",
            )
        if (
            tool.risk is RiskLevel.MEDIUM
            and self.config.require_approval_for_medium_risk
        ):
            return PolicyResult(Decision.REQUIRE_APPROVAL, "medium-risk tool requires approval")
        if (
            tool.side_effect is SideEffect.REVERSIBLE
            and self.config.require_approval_for_reversible_side_effects
        ):
            return PolicyResult(
                Decision.REQUIRE_APPROVAL,
                "reversible side effect requires approval under current policy",
            )
        return PolicyResult(Decision.ALLOW, "tool may execute automatically")


class ExecutionLedger:
    """Store successful idempotent outcomes to suppress duplicate side effects."""

    def __init__(self) -> None:
        self._successful: dict[str, Payload] = {}

    def get(self, key: str) -> Payload | None:
        value = self._successful.get(key)
        return dict(value) if value is not None else None

    def record(self, key: str, output: Payload) -> None:
        self._successful[key] = dict(output)


class GovernedAgentRuntime:
    def __init__(
        self,
        registry: ToolRegistry,
        *,
        policy: ToolPolicy | None = None,
        ledger: ExecutionLedger | None = None,
        max_steps: int = 8,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.registry = registry
        self.policy = policy or ToolPolicy()
        self.ledger = ledger or ExecutionLedger()
        self.max_steps = max_steps

    @staticmethod
    def _idempotency_key(action: PlannedAction) -> str:
        if action.idempotency_key:
            return action.idempotency_key
        canonical = json.dumps(
            {"tool": action.tool, "arguments": action.arguments},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def execute(
        self,
        task: str,
        plan: list[PlannedAction],
        *,
        approved_action_ids: frozenset[str] = frozenset(),
    ) -> ExecutionTrace:
        trace = ExecutionTrace(task=task, planned_actions=len(plan), max_steps=self.max_steps)

        for index, action in enumerate(plan):
            if index >= self.max_steps:
                trace.stopped_reason = "step_budget_exhausted"
                for remaining in plan[index:]:
                    trace.results.append(
                        ActionResult(
                            action_id=remaining.action_id,
                            tool=remaining.tool,
                            status=ActionStatus.SKIPPED_BUDGET,
                            output=None,
                            error=None,
                            policy=PolicyResult(Decision.DENY, "execution step budget exhausted"),
                            idempotency_key=self._idempotency_key(remaining),
                        )
                    )
                break

            key = self._idempotency_key(action)
            try:
                tool = self.registry.get(action.tool)
            except KeyError as exc:
                trace.results.append(
                    ActionResult(
                        action_id=action.action_id,
                        tool=action.tool,
                        status=ActionStatus.DENIED,
                        output=None,
                        error=str(exc),
                        policy=PolicyResult(Decision.DENY, "unknown tool"),
                        idempotency_key=key,
                    )
                )
                continue

            policy_result = self.policy.evaluate(tool)
            if policy_result.decision is Decision.DENY:
                trace.results.append(
                    ActionResult(
                        action.action_id,
                        action.tool,
                        ActionStatus.DENIED,
                        None,
                        None,
                        policy_result,
                        key,
                    )
                )
                continue

            if (
                policy_result.decision is Decision.REQUIRE_APPROVAL
                and action.action_id not in approved_action_ids
            ):
                trace.results.append(
                    ActionResult(
                        action.action_id,
                        action.tool,
                        ActionStatus.AWAITING_APPROVAL,
                        None,
                        None,
                        policy_result,
                        key,
                    )
                )
                continue

            cached = self.ledger.get(key) if tool.idempotent else None
            if cached is not None:
                trace.results.append(
                    ActionResult(
                        action.action_id,
                        action.tool,
                        ActionStatus.REPLAYED,
                        cached,
                        None,
                        policy_result,
                        key,
                    )
                )
                continue

            try:
                if tool.validator:
                    tool.validator(action.arguments)
                output = tool.handler(dict(action.arguments))
                if not isinstance(output, dict):
                    raise TypeError("tool handlers must return dictionaries")
            except (TypeError, ValueError, RuntimeError, OSError) as exc:
                trace.results.append(
                    ActionResult(
                        action.action_id,
                        action.tool,
                        ActionStatus.FAILED,
                        None,
                        f"{type(exc).__name__}: {exc}",
                        policy_result,
                        key,
                    )
                )
                continue

            if tool.idempotent:
                self.ledger.record(key, output)
            trace.results.append(
                ActionResult(
                    action.action_id,
                    action.tool,
                    ActionStatus.SUCCEEDED,
                    output,
                    None,
                    policy_result,
                    key,
                )
            )

        if trace.stopped_reason is None:
            trace.stopped_reason = "plan_completed"
        return trace
