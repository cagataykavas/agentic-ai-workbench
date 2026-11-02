"""Canonical request identities shared by agent execution paths."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, cast

MAX_CANONICAL_REQUEST_BYTES = 65_536


class CanonicalRequestError(ValueError):
    """A tool request cannot be represented by the runtime's strict contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class CanonicalRequestIdentity:
    """A detached JSON argument snapshot and its tool-bound SHA-256 identity."""

    tool: str
    arguments: dict[str, Any]
    sha256: str

    @classmethod
    def from_parts(
        cls,
        tool: str,
        arguments: object,
        *,
        max_bytes: int = MAX_CANONICAL_REQUEST_BYTES,
    ) -> CanonicalRequestIdentity:
        if not isinstance(tool, str) or not tool:
            raise CanonicalRequestError("invalid_tool_name")
        if type(max_bytes) is not int or not 256 <= max_bytes <= 1_048_576:
            raise ValueError("max_bytes must be an integer in [256, 1048576]")
        try:
            encoded = json.dumps(
                {"tool": tool, "arguments": arguments},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise CanonicalRequestError("invalid_json_arguments") from exc
        if len(encoded) > max_bytes:
            raise CanonicalRequestError("argument_budget_exceeded")
        document = json.loads(encoded)
        canonical_arguments = document["arguments"]
        if not isinstance(canonical_arguments, dict):
            raise CanonicalRequestError("arguments_not_object")
        return cls(
            tool=tool,
            arguments=cast(dict[str, Any], canonical_arguments),
            sha256=hashlib.sha256(encoded).hexdigest(),
        )
