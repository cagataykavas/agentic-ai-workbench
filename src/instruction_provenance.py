"""Provenance-aware admission for tool proposals influenced by external content.

The gate deliberately works on digests and lineage metadata rather than raw prompts.
It separates evidence used as *data* from evidence that influenced tool selection or
argument construction, then propagates untrusted taint monotonically through a DAG.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_POINTER_PATTERN = re.compile(r"^/(?:[^~/]|~0|~1)+(?:/(?:[^~/]|~0|~1)+)*$")


class MalformedEvidence(ValueError):
    """The supplied lineage cannot be evaluated safely."""


class SourceKind(str, Enum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    RETRIEVAL = "retrieval"
    TOOL_RESULT = "tool_result"
    MEMORY = "memory"
    DERIVED = "derived"


@dataclass(frozen=True)
class ProvenanceNode:
    node_id: str
    run_id: str
    source: SourceKind
    content_digest: str
    parents: tuple[str, ...] = ()


@dataclass(frozen=True)
class ArgumentBinding:
    path: str
    node_ids: tuple[str, ...]


@dataclass(frozen=True)
class ToolRule:
    tool: str
    required_lineage_paths: frozenset[str] = frozenset()
    allowed_untrusted_data_paths: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ProvenancePolicy:
    policy_id: str
    rules: tuple[ToolRule, ...]
    trusted_control_sources: frozenset[SourceKind] = frozenset(
        {SourceKind.SYSTEM, SourceKind.DEVELOPER, SourceKind.USER}
    )
    max_nodes: int = 1024
    max_parents_per_node: int = 8
    max_bindings: int = 128
    approval_future_skew: timedelta = timedelta(seconds=30)
    max_approval_ttl: timedelta = timedelta(minutes=15)

    @property
    def digest(self) -> str:
        document = {
            "policy_id": self.policy_id,
            "trusted_control_sources": sorted(source.value for source in self.trusted_control_sources),
            "max_nodes": self.max_nodes,
            "max_parents_per_node": self.max_parents_per_node,
            "max_bindings": self.max_bindings,
            "approval_future_skew_seconds": self.approval_future_skew.total_seconds(),
            "max_approval_ttl_seconds": self.max_approval_ttl.total_seconds(),
            "rules": [
                {
                    "tool": rule.tool,
                    "required_lineage_paths": sorted(rule.required_lineage_paths),
                    "allowed_untrusted_data_paths": sorted(rule.allowed_untrusted_data_paths),
                }
                for rule in sorted(self.rules, key=lambda item: item.tool)
            ],
        }
        return _sha256(document)


@dataclass(frozen=True)
class ToolProposal:
    run_id: str
    proposal_id: str
    policy_digest: str
    tool: str
    arguments_digest: str
    control_node_ids: tuple[str, ...]
    argument_bindings: tuple[ArgumentBinding, ...]

    @property
    def digest(self) -> str:
        return _sha256(
            {
                "run_id": self.run_id,
                "proposal_id": self.proposal_id,
                "policy_digest": self.policy_digest,
                "tool": self.tool,
                "arguments_digest": self.arguments_digest,
                "control_node_ids": list(self.control_node_ids),
                "argument_bindings": [
                    {"path": binding.path, "node_ids": list(binding.node_ids)}
                    for binding in self.argument_bindings
                ],
            }
        )


@dataclass(frozen=True)
class ApprovalReceipt:
    run_id: str
    proposal_digest: str
    policy_digest: str
    approver_digest: str
    approved_node_ids: frozenset[str]
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class AdmissionReport:
    accepted: bool
    reason_codes: tuple[str, ...]
    evidence_sha256: str
    node_count: int
    tainted_node_count: int
    approved_exception_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "reason_codes": list(self.reason_codes),
            "evidence_sha256": self.evidence_sha256,
            "node_count": self.node_count,
            "tainted_node_count": self.tainted_node_count,
            "approved_exception_count": self.approved_exception_count,
            "schema_version": 1,
        }


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate_id(value: str, label: str) -> None:
    if not isinstance(value, str) or _ID_PATTERN.fullmatch(value) is None:
        raise MalformedEvidence(f"invalid {label}")


def _validate_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or _DIGEST_PATTERN.fullmatch(value) is None:
        raise MalformedEvidence(f"invalid {label}")


def _validate_pointer(value: str) -> None:
    if not isinstance(value, str) or len(value) > 256 or _POINTER_PATTERN.fullmatch(value) is None:
        raise MalformedEvidence("invalid JSON pointer")


def _validate_policy(policy: ProvenancePolicy) -> dict[str, ToolRule]:
    _validate_id(policy.policy_id, "policy ID")
    if not 1 <= policy.max_nodes <= 100_000:
        raise MalformedEvidence("invalid node budget")
    if not 1 <= policy.max_parents_per_node <= 64:
        raise MalformedEvidence("invalid parent budget")
    if not 1 <= policy.max_bindings <= 10_000:
        raise MalformedEvidence("invalid binding budget")
    if not timedelta(0) <= policy.approval_future_skew <= timedelta(minutes=5):
        raise MalformedEvidence("invalid approval future-skew budget")
    if not timedelta(seconds=1) <= policy.max_approval_ttl <= timedelta(hours=24):
        raise MalformedEvidence("invalid approval TTL budget")
    if SourceKind.DERIVED in policy.trusted_control_sources:
        raise MalformedEvidence("derived content cannot be a trusted source")

    rules: dict[str, ToolRule] = {}
    for rule in policy.rules:
        _validate_id(rule.tool, "tool name")
        if rule.tool in rules:
            raise MalformedEvidence("duplicate tool rule")
        for path in rule.required_lineage_paths | rule.allowed_untrusted_data_paths:
            _validate_pointer(path)
        rules[rule.tool] = rule
    return rules


def _validate_graph(
    nodes: tuple[ProvenanceNode, ...], policy: ProvenancePolicy, run_id: str
) -> tuple[dict[str, ProvenanceNode], dict[str, bool]]:
    if len(nodes) > policy.max_nodes:
        raise MalformedEvidence("node budget exceeded")

    indexed: dict[str, ProvenanceNode] = {}
    for node in nodes:
        _validate_id(node.node_id, "node ID")
        _validate_id(node.run_id, "node run ID")
        _validate_digest(node.content_digest, "content digest")
        if node.node_id in indexed:
            raise MalformedEvidence("duplicate node ID")
        if node.run_id != run_id:
            raise MalformedEvidence("cross-run provenance node")
        if len(node.parents) > policy.max_parents_per_node:
            raise MalformedEvidence("parent budget exceeded")
        if len(set(node.parents)) != len(node.parents):
            raise MalformedEvidence("duplicate parent reference")
        if node.source is SourceKind.DERIVED and not node.parents:
            raise MalformedEvidence("derived node requires parents")
        if node.source is not SourceKind.DERIVED and node.parents:
            raise MalformedEvidence("source node cannot have parents")
        indexed[node.node_id] = node

    for node in nodes:
        if any(parent not in indexed for parent in node.parents):
            raise MalformedEvidence("unknown parent reference")

    visiting: set[str] = set()
    taint: dict[str, bool] = {}

    def is_tainted(node_id: str) -> bool:
        if node_id in taint:
            return taint[node_id]
        if node_id in visiting:
            raise MalformedEvidence("provenance graph contains a cycle")
        visiting.add(node_id)
        node = indexed[node_id]
        inherited = any(is_tainted(parent) for parent in node.parents)
        source_taint = (
            node.source is not SourceKind.DERIVED and node.source not in policy.trusted_control_sources
        )
        taint[node_id] = source_taint or inherited
        visiting.remove(node_id)
        return taint[node_id]

    for node_id in indexed:
        is_tainted(node_id)
    return indexed, taint


def _validate_proposal(proposal: ToolProposal, policy: ProvenancePolicy) -> None:
    _validate_id(proposal.run_id, "proposal run ID")
    _validate_id(proposal.proposal_id, "proposal ID")
    _validate_id(proposal.tool, "proposal tool")
    _validate_digest(proposal.policy_digest, "proposal policy digest")
    _validate_digest(proposal.arguments_digest, "arguments digest")
    if not proposal.control_node_ids:
        raise MalformedEvidence("control lineage is required")
    if len(set(proposal.control_node_ids)) != len(proposal.control_node_ids):
        raise MalformedEvidence("duplicate control node reference")
    if len(proposal.argument_bindings) > policy.max_bindings:
        raise MalformedEvidence("binding budget exceeded")
    paths: set[str] = set()
    for binding in proposal.argument_bindings:
        _validate_pointer(binding.path)
        if binding.path in paths:
            raise MalformedEvidence("duplicate argument binding")
        if not binding.node_ids or len(set(binding.node_ids)) != len(binding.node_ids):
            raise MalformedEvidence("invalid argument lineage")
        paths.add(binding.path)


def _validate_receipt(
    receipt: ApprovalReceipt,
    proposal: ToolProposal,
    policy: ProvenancePolicy,
    referenced_nodes: set[str],
    now: datetime,
) -> set[str]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise MalformedEvidence("evaluation time must be timezone-aware")
    if (
        receipt.issued_at.tzinfo is None
        or receipt.issued_at.utcoffset() is None
        or receipt.expires_at.tzinfo is None
        or receipt.expires_at.utcoffset() is None
    ):
        raise MalformedEvidence("approval timestamps must be timezone-aware")
    _validate_id(receipt.run_id, "approval run ID")
    _validate_digest(receipt.proposal_digest, "approval proposal digest")
    _validate_digest(receipt.policy_digest, "approval policy digest")
    _validate_digest(receipt.approver_digest, "approver digest")
    for node_id in receipt.approved_node_ids:
        _validate_id(node_id, "approved node ID")
    if not receipt.approved_node_ids <= referenced_nodes:
        raise MalformedEvidence("approval references unrelated nodes")
    if receipt.expires_at <= receipt.issued_at:
        raise MalformedEvidence("approval expiry must follow issuance")
    if receipt.expires_at - receipt.issued_at > policy.max_approval_ttl:
        raise MalformedEvidence("approval TTL budget exceeded")

    binding_matches = (
        receipt.run_id == proposal.run_id
        and receipt.proposal_digest == proposal.digest
        and receipt.policy_digest == policy.digest
    )
    if not binding_matches:
        return set()
    if receipt.issued_at > now + policy.approval_future_skew or receipt.expires_at <= now:
        return set()
    return set(receipt.approved_node_ids)


def audit_instruction_provenance(
    *,
    proposal: ToolProposal,
    nodes: tuple[ProvenanceNode, ...],
    policy: ProvenancePolicy,
    approval: ApprovalReceipt | None = None,
    now: datetime | None = None,
) -> AdmissionReport:
    """Audit one tool proposal without exposing prompts, arguments, or source text."""

    rules = _validate_policy(policy)
    _validate_proposal(proposal, policy)
    indexed, taint = _validate_graph(nodes, policy, proposal.run_id)
    current_time = now or datetime.now(UTC)
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise MalformedEvidence("evaluation time must be timezone-aware")

    referenced = set(proposal.control_node_ids)
    bindings: dict[str, tuple[str, ...]] = {}
    for binding in proposal.argument_bindings:
        referenced.update(binding.node_ids)
        bindings[binding.path] = binding.node_ids
    if any(node_id not in indexed for node_id in referenced):
        raise MalformedEvidence("proposal references unknown provenance node")

    approved_nodes = (
        _validate_receipt(approval, proposal, policy, referenced, current_time)
        if approval is not None
        else set()
    )
    reasons: set[str] = set()
    if proposal.policy_digest != policy.digest:
        reasons.add("POLICY_DIGEST_MISMATCH")

    rule = rules.get(proposal.tool)
    if rule is None:
        reasons.add("TOOL_NOT_GOVERNED")
    else:
        missing_paths = rule.required_lineage_paths - bindings.keys()
        if missing_paths:
            reasons.add("REQUIRED_ARGUMENT_LINEAGE_MISSING")

        for node_id in proposal.control_node_ids:
            if taint[node_id] and node_id not in approved_nodes:
                reasons.add("UNTRUSTED_CONTROL_INFLUENCE")

        for path, node_ids in bindings.items():
            if path in rule.allowed_untrusted_data_paths:
                continue
            if any(taint[node_id] and node_id not in approved_nodes for node_id in node_ids):
                reasons.add("UNTRUSTED_SENSITIVE_ARGUMENT")

    evidence = {
        "policy_digest": policy.digest,
        "proposal_digest": proposal.digest,
        "nodes": [
            {
                "node_id": node.node_id,
                "run_id": node.run_id,
                "source": node.source.value,
                "content_digest": node.content_digest,
                "parents": list(node.parents),
            }
            for node in sorted(nodes, key=lambda item: item.node_id)
        ],
        "approval": None
        if approval is None
        else {
            "run_id": approval.run_id,
            "proposal_digest": approval.proposal_digest,
            "policy_digest": approval.policy_digest,
            "approver_digest": approval.approver_digest,
            "approved_node_ids": sorted(approval.approved_node_ids),
            "issued_at": approval.issued_at.isoformat(),
            "expires_at": approval.expires_at.isoformat(),
        },
    }
    return AdmissionReport(
        accepted=not reasons,
        reason_codes=tuple(sorted(reasons)),
        evidence_sha256=_sha256(evidence),
        node_count=len(indexed),
        tainted_node_count=sum(taint.values()),
        approved_exception_count=len(approved_nodes),
    )
