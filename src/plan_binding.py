from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from src.governed_runtime import (
    ExecutionTrace,
    GovernedAgentRuntime,
    PlannedAction,
    ToolPolicy,
    ToolRegistry,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_ACTIONS = 128
_MAX_JSON_BYTES = 131_072
_MAX_DEPTH = 16
_MAX_NODES = 10_000
_INVALID_RECEIPT_DIGEST = hashlib.sha256(b"invalid-plan-binding-receipt").hexdigest()


class PlanBindingReason(StrEnum):
    ADMITTED = "admitted"
    TASK_OR_PLAN_CHANGED = "task_or_plan_changed"
    TOOL_REGISTRY_CHANGED = "tool_registry_changed"
    POLICY_CHANGED = "policy_changed"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    INVALID_RECEIPT = "invalid_receipt"
    INVALID_CURRENT_CONTEXT = "invalid_current_context"


@dataclass(frozen=True, slots=True)
class ToolContract:
    """Server-owned identity for the external contract of one registered tool."""

    name: str
    version: str
    arguments_schema_digest: str

    def __post_init__(self) -> None:
        _validate_identifier("tool contract name", self.name)
        _validate_identifier("tool contract version", self.version)
        if not _SHA256.fullmatch(self.arguments_schema_digest):
            raise ValueError("arguments_schema_digest must be canonical lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class PlanBindingReceipt:
    schema_version: int
    plan_digest: str
    registry_digest: str
    policy_digest: str
    issued_at: str
    expires_at: str
    action_count: int

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported receipt schema_version")
        for name in ("plan_digest", "registry_digest", "policy_digest"):
            if not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be canonical lowercase SHA-256")
        if not 1 <= self.action_count <= _MAX_ACTIONS:
            raise ValueError("action_count is outside the supported range")
        issued = _parse_timestamp("issued_at", self.issued_at)
        expires = _parse_timestamp("expires_at", self.expires_at)
        if expires <= issued:
            raise ValueError("expires_at must be after issued_at")

    @property
    def receipt_digest(self) -> str:
        return _sha256(asdict(self))

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "receipt_digest": self.receipt_digest}


@dataclass(frozen=True, slots=True)
class PlanBindingAdmission:
    accepted: bool
    reasons: tuple[PlanBindingReason, ...]
    receipt_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "reasons": [reason.value for reason in self.reasons],
            "receipt_digest": self.receipt_digest,
        }


class PlanBindingError(RuntimeError):
    def __init__(self, admission: PlanBindingAdmission) -> None:
        super().__init__(",".join(reason.value for reason in admission.reasons))
        self.admission = admission


def _validate_identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} is invalid")
    return value


def _aware_utc(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(name: str, value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{name} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} is invalid") from exc
    if _timestamp(parsed) != value:
        raise ValueError(f"{name} must be canonical UTC")
    return parsed


def _canonical_json(value: object) -> bytes:
    nodes = 0
    active: set[int] = set()

    def normalize(item: object, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_NODES:
            raise ValueError("JSON node budget exceeded")
        if depth > _MAX_DEPTH:
            raise ValueError("JSON depth budget exceeded")
        if item is None or isinstance(item, (bool, int, str)):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("non-finite JSON number")
            return item
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                raise ValueError("cyclic JSON value")
            active.add(identity)
            try:
                normalized: dict[str, object] = {}
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise TypeError("JSON object keys must be strings")
                    if key in normalized:
                        raise ValueError("duplicate JSON object key")
                    normalized[key] = normalize(child, depth + 1)
                return normalized
            finally:
                active.remove(identity)
        if isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active:
                raise ValueError("cyclic JSON value")
            active.add(identity)
            try:
                return [normalize(child, depth + 1) for child in item]
            finally:
                active.remove(identity)
        raise ValueError("value is not canonical JSON")

    encoded = json.dumps(
        normalize(value, 0),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("canonical JSON byte budget exceeded")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _plan_payload(task: str, plan: Sequence[PlannedAction]) -> dict[str, object]:
    if not isinstance(task, str) or not task or len(task.encode("utf-8")) > 16_384:
        raise ValueError("task must contain between 1 and 16384 UTF-8 bytes")
    if not 1 <= len(plan) <= _MAX_ACTIONS:
        raise ValueError("plan action count is outside the supported range")
    action_ids: set[str] = set()
    actions: list[dict[str, object]] = []
    for action in plan:
        if not isinstance(action, PlannedAction):
            raise TypeError("plan must contain PlannedAction values")
        _validate_identifier("action_id", action.action_id)
        _validate_identifier("tool name", action.tool)
        if action.action_id in action_ids:
            raise ValueError("duplicate action_id")
        action_ids.add(action.action_id)
        if action.idempotency_key is not None:
            _validate_identifier("idempotency_key", action.idempotency_key)
        actions.append(
            {
                "action_id": action.action_id,
                "tool": action.tool,
                "arguments": action.arguments,
                "rationale": action.rationale,
                "idempotency_key": action.idempotency_key,
            }
        )
    return {"task": task, "actions": actions}


def _registry_payload(
    registry: ToolRegistry,
    contracts: Mapping[str, ToolContract],
) -> list[dict[str, object]]:
    names = registry.names
    if set(contracts) != set(names):
        raise ValueError("contracts must exactly cover the active tool registry")
    payload: list[dict[str, object]] = []
    for name in names:
        contract = contracts[name]
        if contract.name != name:
            raise ValueError("tool contract name does not match registry key")
        tool = registry.get(name)
        payload.append(
            {
                "name": name,
                "description_digest": hashlib.sha256(tool.description.encode("utf-8")).hexdigest(),
                "risk": tool.risk.value,
                "side_effect": tool.side_effect.value,
                "idempotent": tool.idempotent,
                "contract_version": contract.version,
                "arguments_schema_digest": contract.arguments_schema_digest,
            }
        )
    return payload


def _policy_payload(policy: ToolPolicy) -> dict[str, object]:
    config = policy.config
    return {
        "denied_tools": sorted(config.denied_tools),
        "require_approval_for_medium_risk": config.require_approval_for_medium_risk,
        "require_approval_for_reversible_side_effects": (config.require_approval_for_reversible_side_effects),
    }


def bind_plan(
    *,
    task: str,
    plan: Sequence[PlannedAction],
    registry: ToolRegistry,
    policy: ToolPolicy,
    contracts: Mapping[str, ToolContract],
    issued_at: datetime,
    ttl_seconds: int = 300,
) -> PlanBindingReceipt:
    """Bind a plan to the exact server-owned execution context that reviewed it."""

    issued = _aware_utc("issued_at", issued_at)
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise TypeError("ttl_seconds must be an integer")
    if not 30 <= ttl_seconds <= 3600:
        raise ValueError("ttl_seconds must be between 30 and 3600")
    plan_payload = _plan_payload(task, plan)
    planned_tools = {action.tool for action in plan}
    if not planned_tools.issubset(set(registry.names)):
        raise ValueError("plan references an unknown tool")
    return PlanBindingReceipt(
        schema_version=1,
        plan_digest=_sha256(plan_payload),
        registry_digest=_sha256(_registry_payload(registry, contracts)),
        policy_digest=_sha256(_policy_payload(policy)),
        issued_at=_timestamp(issued),
        expires_at=_timestamp(issued + timedelta(seconds=ttl_seconds)),
        action_count=len(plan),
    )


def verify_plan_binding(
    receipt: PlanBindingReceipt,
    *,
    task: str,
    plan: Sequence[PlannedAction],
    registry: ToolRegistry,
    policy: ToolPolicy,
    contracts: Mapping[str, ToolContract],
    now: datetime,
    max_future_skew_seconds: int = 5,
) -> PlanBindingAdmission:
    """Recompute every binding immediately before dispatch and fail closed on drift."""

    try:
        if not isinstance(receipt, PlanBindingReceipt):
            raise TypeError("receipt must be a PlanBindingReceipt")
        receipt = PlanBindingReceipt(**asdict(receipt))
        current = _aware_utc("now", now)
        if not 0 <= max_future_skew_seconds <= 60:
            raise ValueError("max_future_skew_seconds must be between zero and 60")
        issued = _parse_timestamp("issued_at", receipt.issued_at)
        expires = _parse_timestamp("expires_at", receipt.expires_at)
    except (TypeError, ValueError):
        return PlanBindingAdmission(
            False,
            (PlanBindingReason.INVALID_RECEIPT,),
            _INVALID_RECEIPT_DIGEST,
        )

    reasons: list[PlanBindingReason] = []
    if issued > current + timedelta(seconds=max_future_skew_seconds):
        reasons.append(PlanBindingReason.NOT_YET_VALID)
    if current >= expires:
        reasons.append(PlanBindingReason.EXPIRED)
    try:
        if receipt.action_count != len(plan) or receipt.plan_digest != _sha256(_plan_payload(task, plan)):
            reasons.append(PlanBindingReason.TASK_OR_PLAN_CHANGED)
        if receipt.registry_digest != _sha256(_registry_payload(registry, contracts)):
            reasons.append(PlanBindingReason.TOOL_REGISTRY_CHANGED)
        if receipt.policy_digest != _sha256(_policy_payload(policy)):
            reasons.append(PlanBindingReason.POLICY_CHANGED)
    except (KeyError, TypeError, ValueError):
        reasons.append(PlanBindingReason.INVALID_CURRENT_CONTEXT)

    deduplicated = tuple(dict.fromkeys(reasons))
    if not deduplicated:
        deduplicated = (PlanBindingReason.ADMITTED,)
    return PlanBindingAdmission(
        accepted=deduplicated == (PlanBindingReason.ADMITTED,),
        reasons=deduplicated,
        receipt_digest=receipt.receipt_digest,
    )


def execute_bound_plan(
    runtime: GovernedAgentRuntime,
    *,
    receipt: PlanBindingReceipt,
    task: str,
    plan: Sequence[PlannedAction],
    contracts: Mapping[str, ToolContract],
    now: datetime,
    approved_action_ids: frozenset[str] = frozenset(),
) -> ExecutionTrace:
    """Verify a binding at the last responsible moment, then invoke the runtime."""

    admission = verify_plan_binding(
        receipt,
        task=task,
        plan=plan,
        registry=runtime.registry,
        policy=runtime.policy,
        contracts=contracts,
        now=now,
    )
    if not admission.accepted:
        raise PlanBindingError(admission)
    return runtime.execute(
        task,
        list(plan),
        approved_action_ids=approved_action_ids,
    )
