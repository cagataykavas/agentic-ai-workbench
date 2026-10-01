from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from src.instruction_provenance import (
    ApprovalReceipt,
    ArgumentBinding,
    MalformedEvidence,
    ProvenanceNode,
    ProvenancePolicy,
    SourceKind,
    ToolProposal,
    ToolRule,
    audit_instruction_provenance,
)

NOW = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def policy() -> ProvenancePolicy:
    return ProvenancePolicy(
        policy_id="agent-tools-v1",
        rules=(
            ToolRule(
                tool="send_email",
                required_lineage_paths=frozenset({"/recipient", "/body"}),
                allowed_untrusted_data_paths=frozenset({"/body"}),
            ),
        ),
    )


def nodes() -> tuple[ProvenanceNode, ...]:
    return (
        ProvenanceNode("user-intent", "run-1", SourceKind.USER, digest("send summary")),
        ProvenanceNode("recipient", "run-1", SourceKind.USER, digest("approved recipient")),
        ProvenanceNode("retrieved-body", "run-1", SourceKind.RETRIEVAL, digest("external text")),
        ProvenanceNode(
            "formatted-body",
            "run-1",
            SourceKind.DERIVED,
            digest("formatted external text"),
            ("retrieved-body",),
        ),
    )


def proposal(current_policy: ProvenancePolicy | None = None) -> ToolProposal:
    selected_policy = current_policy or policy()
    return ToolProposal(
        run_id="run-1",
        proposal_id="proposal-1",
        policy_digest=selected_policy.digest,
        tool="send_email",
        arguments_digest=digest("canonical arguments"),
        control_node_ids=("user-intent",),
        argument_bindings=(
            ArgumentBinding("/recipient", ("recipient",)),
            ArgumentBinding("/body", ("formatted-body",)),
        ),
    )


def approval_for(
    current_proposal: ToolProposal,
    current_policy: ProvenancePolicy,
    approved_nodes: frozenset[str],
) -> ApprovalReceipt:
    return ApprovalReceipt(
        run_id=current_proposal.run_id,
        proposal_digest=current_proposal.digest,
        policy_digest=current_policy.digest,
        approver_digest=digest("reviewer-42"),
        approved_node_ids=approved_nodes,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
    )


def test_allows_untrusted_content_only_in_explicit_data_path() -> None:
    report = audit_instruction_provenance(proposal=proposal(), nodes=nodes(), policy=policy(), now=NOW)
    assert report.accepted
    assert report.reason_codes == ()
    assert report.tainted_node_count == 2


def test_rejects_retrieval_content_that_influences_tool_control() -> None:
    current = replace(proposal(), control_node_ids=("user-intent", "retrieved-body"))
    report = audit_instruction_provenance(proposal=current, nodes=nodes(), policy=policy(), now=NOW)
    assert not report.accepted
    assert report.reason_codes == ("UNTRUSTED_CONTROL_INFLUENCE",)


def test_taint_is_monotonic_through_derived_nodes() -> None:
    current = replace(proposal(), control_node_ids=("formatted-body",))
    report = audit_instruction_provenance(proposal=current, nodes=nodes(), policy=policy(), now=NOW)
    assert report.reason_codes == ("UNTRUSTED_CONTROL_INFLUENCE",)


def test_rejects_untrusted_sensitive_argument() -> None:
    current = replace(
        proposal(),
        argument_bindings=(
            ArgumentBinding("/recipient", ("retrieved-body",)),
            ArgumentBinding("/body", ("formatted-body",)),
        ),
    )
    report = audit_instruction_provenance(proposal=current, nodes=nodes(), policy=policy(), now=NOW)
    assert report.reason_codes == ("UNTRUSTED_SENSITIVE_ARGUMENT",)


def test_allowed_data_path_matches_exactly_not_by_prefix() -> None:
    permissive = ProvenancePolicy(
        policy_id="exact-paths",
        rules=(
            ToolRule(
                "send_email",
                required_lineage_paths=frozenset({"/body/recipient"}),
                allowed_untrusted_data_paths=frozenset({"/body"}),
            ),
        ),
    )
    current = replace(
        proposal(permissive),
        argument_bindings=(ArgumentBinding("/body/recipient", ("retrieved-body",)),),
    )
    report = audit_instruction_provenance(proposal=current, nodes=nodes(), policy=permissive, now=NOW)
    assert report.reason_codes == ("UNTRUSTED_SENSITIVE_ARGUMENT",)


def test_scoped_approval_can_authorize_exact_tainted_nodes() -> None:
    current_policy = policy()
    current = replace(
        proposal(current_policy),
        control_node_ids=("retrieved-body",),
        argument_bindings=(
            ArgumentBinding("/recipient", ("retrieved-body",)),
            ArgumentBinding("/body", ("formatted-body",)),
        ),
    )
    receipt = approval_for(current, current_policy, frozenset({"retrieved-body"}))
    report = audit_instruction_provenance(
        proposal=current,
        nodes=nodes(),
        policy=current_policy,
        approval=receipt,
        now=NOW,
    )
    assert report.accepted
    assert report.approved_exception_count == 1


@pytest.mark.parametrize("field", ["run_id", "proposal_digest", "policy_digest"])
def test_approval_binding_mismatch_does_not_declassify(field: str) -> None:
    current_policy = policy()
    current = replace(proposal(current_policy), control_node_ids=("retrieved-body",))
    receipt = approval_for(current, current_policy, frozenset({"retrieved-body"}))
    replacement = "other-run" if field == "run_id" else digest(f"other-{field}")
    receipt = replace(receipt, **{field: replacement})
    report = audit_instruction_provenance(
        proposal=current,
        nodes=nodes(),
        policy=current_policy,
        approval=receipt,
        now=NOW,
    )
    assert report.reason_codes == ("UNTRUSTED_CONTROL_INFLUENCE",)
    assert report.approved_exception_count == 0


def test_expired_or_future_approval_does_not_declassify() -> None:
    current_policy = policy()
    current = replace(proposal(current_policy), control_node_ids=("retrieved-body",))
    receipt = approval_for(current, current_policy, frozenset({"retrieved-body"}))

    expired = replace(receipt, issued_at=NOW - timedelta(minutes=10), expires_at=NOW)
    future = replace(
        receipt,
        issued_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=2),
    )
    for candidate in (expired, future):
        report = audit_instruction_provenance(
            proposal=current,
            nodes=nodes(),
            policy=current_policy,
            approval=candidate,
            now=NOW,
        )
        assert report.reason_codes == ("UNTRUSTED_CONTROL_INFLUENCE",)


def test_rejects_unknown_tool_and_policy_drift() -> None:
    current = replace(proposal(), tool="shell", policy_digest=digest("stale policy"))
    report = audit_instruction_provenance(proposal=current, nodes=nodes(), policy=policy(), now=NOW)
    assert report.reason_codes == ("POLICY_DIGEST_MISMATCH", "TOOL_NOT_GOVERNED")


def test_rejects_missing_required_argument_lineage() -> None:
    current = replace(proposal(), argument_bindings=(ArgumentBinding("/body", ("formatted-body",)),))
    report = audit_instruction_provenance(proposal=current, nodes=nodes(), policy=policy(), now=NOW)
    assert report.reason_codes == ("REQUIRED_ARGUMENT_LINEAGE_MISSING",)


def test_report_is_deterministic_and_contains_no_raw_content() -> None:
    first = audit_instruction_provenance(
        proposal=proposal(), nodes=nodes(), policy=policy(), now=NOW
    ).to_dict()
    second = audit_instruction_provenance(
        proposal=proposal(), nodes=tuple(reversed(nodes())), policy=policy(), now=NOW
    ).to_dict()
    assert first == second
    serialized = str(first)
    assert "external text" not in serialized
    assert len(first["evidence_sha256"]) == 64


def test_rejects_duplicate_nodes_and_unknown_parents() -> None:
    with pytest.raises(MalformedEvidence, match="duplicate node"):
        audit_instruction_provenance(
            proposal=proposal(), nodes=nodes() + (nodes()[0],), policy=policy(), now=NOW
        )
    broken = replace(nodes()[-1], parents=("missing",))
    with pytest.raises(MalformedEvidence, match="unknown parent"):
        audit_instruction_provenance(
            proposal=proposal(), nodes=nodes()[:-1] + (broken,), policy=policy(), now=NOW
        )


def test_rejects_cycles_and_cross_run_nodes() -> None:
    cycle = (
        ProvenanceNode("a", "run-1", SourceKind.DERIVED, digest("a"), ("b",)),
        ProvenanceNode("b", "run-1", SourceKind.DERIVED, digest("b"), ("a",)),
    )
    with pytest.raises(MalformedEvidence, match="cycle"):
        audit_instruction_provenance(
            proposal=replace(proposal(), control_node_ids=("a",)),
            nodes=cycle,
            policy=policy(),
            now=NOW,
        )
    cross_run = replace(nodes()[0], run_id="run-2")
    with pytest.raises(MalformedEvidence, match="cross-run"):
        audit_instruction_provenance(
            proposal=proposal(), nodes=(cross_run,) + nodes()[1:], policy=policy(), now=NOW
        )


def test_rejects_source_parent_laundering_and_parent_budget() -> None:
    laundering = replace(nodes()[0], parents=("retrieved-body",))
    with pytest.raises(MalformedEvidence, match="source node"):
        audit_instruction_provenance(
            proposal=proposal(), nodes=(laundering,) + nodes()[1:], policy=policy(), now=NOW
        )
    constrained = replace(policy(), max_parents_per_node=1)
    combined = ProvenanceNode(
        "combined",
        "run-1",
        SourceKind.DERIVED,
        digest("combined"),
        ("user-intent", "retrieved-body"),
    )
    with pytest.raises(MalformedEvidence, match="parent budget"):
        audit_instruction_provenance(
            proposal=proposal(constrained),
            nodes=nodes() + (combined,),
            policy=constrained,
            now=NOW,
        )


def test_rejects_resource_budget_breaches() -> None:
    constrained = replace(policy(), max_nodes=3)
    with pytest.raises(MalformedEvidence, match="node budget"):
        audit_instruction_provenance(
            proposal=proposal(constrained), nodes=nodes(), policy=constrained, now=NOW
        )
    constrained = replace(policy(), max_bindings=1)
    with pytest.raises(MalformedEvidence, match="binding budget"):
        audit_instruction_provenance(
            proposal=proposal(constrained), nodes=nodes(), policy=constrained, now=NOW
        )


def test_rejects_duplicate_bindings_and_unrelated_approval_nodes() -> None:
    duplicate = replace(
        proposal(),
        argument_bindings=(
            ArgumentBinding("/body", ("formatted-body",)),
            ArgumentBinding("/body", ("retrieved-body",)),
        ),
    )
    with pytest.raises(MalformedEvidence, match="duplicate argument binding"):
        audit_instruction_provenance(proposal=duplicate, nodes=nodes(), policy=policy(), now=NOW)

    current_policy = policy()
    current = proposal(current_policy)
    receipt = approval_for(current, current_policy, frozenset({"not-referenced"}))
    with pytest.raises(MalformedEvidence, match="unrelated"):
        audit_instruction_provenance(
            proposal=current,
            nodes=nodes(),
            policy=current_policy,
            approval=receipt,
            now=NOW,
        )


def test_rejects_malformed_ids_digests_pointers_and_timestamps() -> None:
    with pytest.raises(MalformedEvidence, match="arguments digest"):
        audit_instruction_provenance(
            proposal=replace(proposal(), arguments_digest="bad"),
            nodes=nodes(),
            policy=policy(),
            now=NOW,
        )
    bad_binding = replace(proposal(), argument_bindings=(ArgumentBinding("recipient", ("recipient",)),))
    with pytest.raises(MalformedEvidence, match="JSON pointer"):
        audit_instruction_provenance(proposal=bad_binding, nodes=nodes(), policy=policy(), now=NOW)
    with pytest.raises(MalformedEvidence, match="timezone-aware"):
        audit_instruction_provenance(
            proposal=proposal(), nodes=nodes(), policy=policy(), now=NOW.replace(tzinfo=None)
        )
    current_policy = policy()
    current = proposal(current_policy)
    long_lived = replace(
        approval_for(current, current_policy, frozenset()),
        expires_at=NOW + timedelta(hours=1),
    )
    with pytest.raises(MalformedEvidence, match="TTL budget"):
        audit_instruction_provenance(
            proposal=current,
            nodes=nodes(),
            policy=current_policy,
            approval=long_lived,
            now=NOW,
        )


def test_rejects_duplicate_tool_rules_and_derived_trust() -> None:
    duplicate = replace(policy(), rules=policy().rules * 2)
    with pytest.raises(MalformedEvidence, match="duplicate tool rule"):
        audit_instruction_provenance(proposal=proposal(duplicate), nodes=nodes(), policy=duplicate, now=NOW)
    unsafe = replace(
        policy(), trusted_control_sources=policy().trusted_control_sources | {SourceKind.DERIVED}
    )
    with pytest.raises(MalformedEvidence, match="derived content"):
        audit_instruction_provenance(proposal=proposal(unsafe), nodes=nodes(), policy=unsafe, now=NOW)
