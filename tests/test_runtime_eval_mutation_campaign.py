from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from src.runtime_eval_mutation_campaign import (
    MUTATION_CAMPAIGN_SCHEMA,
    MUTANT_BOUNDARIES,
    SUPPORTED_MUTANTS,
    MutationCampaignError,
    evaluate_runtime_safety_mutants,
    run_runtime_safety_mutation_campaign,
    summarize_mutation_campaign,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def test_reviewed_suite_kills_every_supported_unsafe_mutant() -> None:
    outcomes = evaluate_runtime_safety_mutants()

    assert tuple(outcome.mutant for outcome in outcomes) == SUPPORTED_MUTANTS
    assert all(outcome.killed for outcome in outcomes)
    assert all(outcome.detected_boundary is MUTANT_BOUNDARIES[outcome.mutant] for outcome in outcomes)


def test_campaign_receipt_is_deterministic_private_and_self_digested() -> None:
    receipts = [run_runtime_safety_mutation_campaign() for _ in range(5)]
    assert receipts.count(receipts[0]) == len(receipts)

    receipt = receipts[0]
    assert receipt["schema_version"] == MUTATION_CAMPAIGN_SCHEMA
    assert receipt["status"] == "pass"
    assert receipt["mutant_count"] == len(SUPPORTED_MUTANTS)
    assert receipt["killed_count"] == len(SUPPORTED_MUTANTS)
    assert receipt["survived_count"] == 0
    digest = receipt.pop("evidence_sha256")
    assert digest == hashlib.sha256(_canonical(receipt)).hexdigest()
    serialized = json.dumps(receipt)
    for private in (
        "lookup",
        "publish",
        "unstable",
        "not-registered",
        "reviewed-scenario",
        "reviewed-replay-key",
        "controlled benchmark failure",
    ):
        assert private not in serialized


def test_campaign_fails_closed_if_a_mutant_survives() -> None:
    outcomes = evaluate_runtime_safety_mutants()
    survived = replace(outcomes[0], detected_boundary=None, killed=False)

    with pytest.raises(MutationCampaignError, match="mutant_survived"):
        summarize_mutation_campaign((survived, *outcomes[1:]))


def test_campaign_rejects_missing_duplicate_or_misclassified_results() -> None:
    outcomes = evaluate_runtime_safety_mutants()

    with pytest.raises(MutationCampaignError, match="mutation_outcome_count_mismatch"):
        summarize_mutation_campaign(outcomes[:-1])
    with pytest.raises(MutationCampaignError, match="duplicate_mutation_outcome"):
        summarize_mutation_campaign((outcomes[0], *outcomes[:-1]))
    wrong_boundary = replace(
        outcomes[0],
        expected_boundary=outcomes[1].expected_boundary,
        detected_boundary=outcomes[1].expected_boundary,
    )
    with pytest.raises(MutationCampaignError, match="mutant_boundary_mismatch"):
        summarize_mutation_campaign((wrong_boundary, *outcomes[1:]))
