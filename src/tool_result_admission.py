from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any

JsonObject = dict[str, Any]


class ToolResultRejected(ValueError):
    """A stable, safe-to-log rejection from the tool-result boundary."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class ToolResultPolicy:
    """Resource and shape limits for untrusted tool output."""

    max_serialized_bytes: int = 32_768
    max_depth: int = 8
    max_container_items: int = 256
    max_total_nodes: int = 2_048
    max_string_bytes: int = 4_096
    max_key_bytes: int = 128

    def __post_init__(self) -> None:
        limits = {
            "max_serialized_bytes": self.max_serialized_bytes,
            "max_depth": self.max_depth,
            "max_container_items": self.max_container_items,
            "max_total_nodes": self.max_total_nodes,
            "max_string_bytes": self.max_string_bytes,
            "max_key_bytes": self.max_key_bytes,
        }
        for name, value in limits.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class AdmittedToolResult:
    """Immutable canonical evidence for a validated tool result."""

    tool: str
    canonical_json: str
    sha256: str
    serialized_bytes: int

    @property
    def payload(self) -> JsonObject:
        # Decode on access so callers cannot mutate the evidence held by a ledger.
        value = json.loads(self.canonical_json)
        if not isinstance(value, dict):  # Defensive invariant; admission requires an object.
            raise TypeError("admitted tool result is not a JSON object")
        return value

    def context_envelope(self) -> JsonObject:
        """Return an explicit trust-boundary envelope for a downstream prompt builder."""

        return {
            "trust": "untrusted_tool_output",
            "tool": self.tool,
            "content_sha256": self.sha256,
            "content": self.payload,
        }


def _reject(code: str, detail: str) -> None:
    raise ToolResultRejected(code, detail)


def _normalize_json(
    value: Any,
    *,
    policy: ToolResultPolicy,
    depth: int,
    active_containers: set[int],
    node_count: list[int],
) -> Any:
    if depth > policy.max_depth:
        _reject("depth_exceeded", f"tool result exceeds max depth {policy.max_depth}")

    node_count[0] += 1
    if node_count[0] > policy.max_total_nodes:
        _reject("node_budget_exceeded", f"tool result exceeds {policy.max_total_nodes} nodes")

    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _reject("non_finite_number", "tool result contains a non-finite number")
        return value
    if isinstance(value, str):
        size = len(value.encode("utf-8"))
        if size > policy.max_string_bytes:
            _reject(
                "string_too_large",
                f"tool result string is {size} bytes; limit is {policy.max_string_bytes}",
            )
        return value

    if not isinstance(value, (dict, list)):
        _reject("unsupported_type", f"tool result contains unsupported type {type(value).__name__}")

    identity = id(value)
    if identity in active_containers:
        _reject("cyclic_structure", "tool result contains a cyclic container")
    if len(value) > policy.max_container_items:
        _reject(
            "container_too_large",
            f"tool result container has {len(value)} items; limit is {policy.max_container_items}",
        )

    active_containers.add(identity)
    try:
        if isinstance(value, list):
            return [
                _normalize_json(
                    item,
                    policy=policy,
                    depth=depth + 1,
                    active_containers=active_containers,
                    node_count=node_count,
                )
                for item in value
            ]

        keys = list(value)
        if any(not isinstance(key, str) for key in keys):
            _reject("non_string_key", "tool result object contains a non-string key")

        normalized: JsonObject = {}
        for key in sorted(keys):
            key_size = len(key.encode("utf-8"))
            if key_size > policy.max_key_bytes:
                _reject(
                    "key_too_large",
                    f"tool result key is {key_size} bytes; limit is {policy.max_key_bytes}",
                )
            normalized[key] = _normalize_json(
                value[key],
                policy=policy,
                depth=depth + 1,
                active_containers=active_containers,
                node_count=node_count,
            )
        return normalized
    finally:
        active_containers.remove(identity)


def admit_tool_result(
    output: Any,
    *,
    tool: str,
    policy: ToolResultPolicy | None = None,
) -> AdmittedToolResult:
    """Validate and canonically encode one untrusted tool result.

    The boundary accepts JSON objects only. It intentionally does not interpret
    strings or claim to detect prompt injection; consumers must preserve the
    returned trust label when placing content in a model context.
    """

    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("tool must be a non-empty string")
    active_policy = policy or ToolResultPolicy()
    if not isinstance(output, dict):
        _reject("root_not_object", "tool handlers must return JSON objects")

    normalized = _normalize_json(
        output,
        policy=active_policy,
        depth=0,
        active_containers=set(),
        node_count=[0],
    )
    canonical = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    encoded = canonical.encode("utf-8")
    if len(encoded) > active_policy.max_serialized_bytes:
        _reject(
            "serialized_size_exceeded",
            f"tool result is {len(encoded)} bytes; limit is {active_policy.max_serialized_bytes}",
        )

    return AdmittedToolResult(
        tool=tool,
        canonical_json=canonical,
        sha256=hashlib.sha256(encoded).hexdigest(),
        serialized_bytes=len(encoded),
    )
