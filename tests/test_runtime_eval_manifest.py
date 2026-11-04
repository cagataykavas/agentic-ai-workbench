from __future__ import annotations

import json
from dataclasses import replace

import pytest

from src.governed_runtime import (
    ActionResult,
    ActionStatus,
    Decision,
    ExecutionTrace,
    PolicyResult,
)
from src.runtime_eval import (
    RuntimeEvaluationError,
    RuntimeGatePolicy,
    RuntimeGateReport,
    evaluate_traces,
)
from src.runtime_eval_manifest import (
    MAX_KEYRING_KEYS,
    MAX_MANIFEST_BYTES,
    RuntimeBenchmarkManifestError,
    dump_runtime_benchmark_manifest,
    evaluate_and_sign_runtime_benchmark,
    evaluate_and_verify_runtime_benchmark,
    load_runtime_benchmark_manifest,
    runtime_evaluation_evidence_sha256,
    sign_runtime_benchmark_manifest,
    verify_runtime_benchmark_manifest,
)

SCENARIO_SUITE_SHA256 = "a" * 64
EVALUATION_EVIDENCE_SHA256 = "c" * 64
SOURCE_REVISION = "b" * 40
RUNTIME_VERSION = "agent-runtime-0.2.0"
KEY_ID = "benchmark-signing-v1"
SECRET = b"runtime-benchmark-signing-secret-v1"


def _report(*, failed: bool = False) -> RuntimeGateReport:
    status = ActionStatus.FAILED if failed else ActionStatus.SUCCEEDED
    trace = ExecutionTrace(
        task="private benchmark task",
        planned_actions=1,
        max_steps=1,
        results=[
            ActionResult(
                action_id="private-action-id",
                tool="private-tool-name",
                status=status,
                output=None if failed else {"private": "payload"},
                error="private-error" if failed else None,
                policy=PolicyResult(Decision.ALLOW, "private-policy-reason"),
                idempotency_key="private-ledger-key",
            )
        ],
        stopped_reason="plan_completed",
    )
    return evaluate_traces(
        [trace],
        RuntimeGatePolicy(maximum_failure_rate=1.0),
    )


def _trace(
    *,
    status: ActionStatus = ActionStatus.SUCCEEDED,
    action_id: str = "private-action-id",
    output: dict[str, str] | None = None,
) -> ExecutionTrace:
    return ExecutionTrace(
        task="private benchmark task",
        planned_actions=1,
        max_steps=1,
        results=[
            ActionResult(
                action_id=action_id,
                tool="private-tool-name",
                status=status,
                output=(output or {"private": "payload"}) if status is ActionStatus.SUCCEEDED else None,
                error="private-error" if status is ActionStatus.FAILED else None,
                policy=PolicyResult(Decision.ALLOW, "private-policy-reason"),
                idempotency_key="private-ledger-key",
            )
        ],
        stopped_reason="plan_completed",
    )


def _manifest(report: RuntimeGateReport | None = None):
    return sign_runtime_benchmark_manifest(
        report or _report(),
        scenario_suite_sha256=SCENARIO_SUITE_SHA256,
        evaluation_evidence_sha256=EVALUATION_EVIDENCE_SHA256,
        runtime_version=RUNTIME_VERSION,
        source_revision=SOURCE_REVISION,
        key_id=KEY_ID,
        secret=SECRET,
    )


def _verify(report: RuntimeGateReport, manifest, *, keyring=None) -> str:
    return verify_runtime_benchmark_manifest(
        report,
        manifest,
        expected_scenario_suite_sha256=SCENARIO_SUITE_SHA256,
        expected_evaluation_evidence_sha256=EVALUATION_EVIDENCE_SHA256,
        expected_runtime_version=RUNTIME_VERSION,
        expected_source_revision=SOURCE_REVISION,
        keyring=keyring or {KEY_ID: SECRET},
    )


def test_signed_manifest_round_trips_and_verifies_commitment() -> None:
    report = _report()
    manifest = _manifest(report)

    loaded = load_runtime_benchmark_manifest(dump_runtime_benchmark_manifest(manifest))

    assert loaded == manifest
    assert _verify(report, loaded) == manifest.sha256


def test_evaluate_then_sign_binds_the_recomputed_report_and_trace_evidence() -> None:
    trace = _trace()
    policy = RuntimeGatePolicy(maximum_failure_rate=0.0)

    report, manifest = evaluate_and_sign_runtime_benchmark(
        [trace],
        policy,
        scenario_suite_sha256=SCENARIO_SUITE_SHA256,
        runtime_version=RUNTIME_VERSION,
        source_revision=SOURCE_REVISION,
        key_id=KEY_ID,
        secret=SECRET,
    )
    verified_report, commitment = evaluate_and_verify_runtime_benchmark(
        [trace],
        policy,
        manifest,
        expected_scenario_suite_sha256=SCENARIO_SUITE_SHA256,
        expected_runtime_version=RUNTIME_VERSION,
        expected_source_revision=SOURCE_REVISION,
        keyring={KEY_ID: SECRET},
    )

    assert report == verified_report
    assert manifest.evaluation_evidence_sha256 == runtime_evaluation_evidence_sha256([trace])
    assert commitment == manifest.sha256


def test_evaluate_then_verify_rejects_trace_evidence_substitution() -> None:
    trace = _trace()
    policy = RuntimeGatePolicy(maximum_failure_rate=1.0)
    _, manifest = evaluate_and_sign_runtime_benchmark(
        [trace],
        policy,
        scenario_suite_sha256=SCENARIO_SUITE_SHA256,
        runtime_version=RUNTIME_VERSION,
        source_revision=SOURCE_REVISION,
        key_id=KEY_ID,
        secret=SECRET,
    )
    substituted = _trace(status=ActionStatus.FAILED)

    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_evaluation_evidence_mismatch"):
        evaluate_and_verify_runtime_benchmark(
            [substituted],
            policy,
            manifest,
            expected_scenario_suite_sha256=SCENARIO_SUITE_SHA256,
            expected_runtime_version=RUNTIME_VERSION,
            expected_source_revision=SOURCE_REVISION,
            keyring={KEY_ID: SECRET},
        )


def test_evidence_digest_is_privacy_reduced_but_binds_gate_relevant_structure() -> None:
    baseline = _trace()
    same_shape = _trace(output={"different-private": "value"})
    different_action = _trace(action_id="different-action")

    assert runtime_evaluation_evidence_sha256([baseline]) == runtime_evaluation_evidence_sha256([same_shape])
    assert runtime_evaluation_evidence_sha256([baseline]) != runtime_evaluation_evidence_sha256(
        [different_action]
    )


def test_evaluate_then_sign_fails_closed_if_evidence_changes(monkeypatch) -> None:
    observed = iter(("a" * 64, "b" * 64))
    monkeypatch.setattr(
        "src.runtime_eval_manifest.runtime_evaluation_evidence_sha256",
        lambda traces: next(observed),
    )

    with pytest.raises(RuntimeEvaluationError, match="trace_set_changed_during_evaluation"):
        evaluate_and_sign_runtime_benchmark(
            [_trace()],
            RuntimeGatePolicy(),
            scenario_suite_sha256=SCENARIO_SUITE_SHA256,
            runtime_version=RUNTIME_VERSION,
            source_revision=SOURCE_REVISION,
            key_id=KEY_ID,
            secret=SECRET,
        )


def test_signer_revalidates_report_invariants_at_the_trust_boundary() -> None:
    report = _report()
    object.__setattr__(report.metrics, "success_rate", 0.5)

    with pytest.raises(ValueError, match="aggregate count"):
        _manifest(report)


def test_manifest_excludes_private_trace_payloads() -> None:
    serialized = dump_runtime_benchmark_manifest(_manifest())

    for private_value in (
        "private benchmark task",
        "private-action-id",
        "private-tool-name",
        "private-policy-reason",
        "private-ledger-key",
        "payload",
    ):
        assert private_value not in serialized


@pytest.mark.parametrize(
    "field",
    [
        "scenario_suite_sha256",
        "evaluation_evidence_sha256",
        "runtime_version",
        "source_revision",
        "policy_sha256",
        "report_sha256",
        "trace_count",
        "planned_actions",
    ],
)
def test_authenticated_field_tampering_is_rejected_before_binding_checks(field: str) -> None:
    report = _report()
    manifest = _manifest(report)
    replacements = {
        "scenario_suite_sha256": "c" * 64,
        "evaluation_evidence_sha256": "d" * 64,
        "runtime_version": "agent-runtime-9.9.9",
        "source_revision": "d" * 40,
        "policy_sha256": "e" * 64,
        "report_sha256": "f" * 64,
        "trace_count": 2,
        "planned_actions": 2,
    }

    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_signature_invalid"):
        _verify(report, replace(manifest, **{field: replacements[field]}))


def test_report_substitution_is_rejected_after_authentication() -> None:
    manifest = _manifest(_report())

    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_report_mismatch"):
        _verify(_report(failed=True), manifest)


def test_unknown_key_and_wrong_secret_are_rejected() -> None:
    report = _report()
    manifest = _manifest(report)

    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_key_unknown"):
        _verify(report, manifest, keyring={"retired-key": SECRET})
    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_signature_invalid"):
        _verify(report, manifest, keyring={KEY_ID: b"x" * 32})


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"expected_scenario_suite_sha256": "c" * 64}, "manifest_scenario_suite_mismatch"),
        (
            {"expected_evaluation_evidence_sha256": "d" * 64},
            "manifest_evaluation_evidence_mismatch",
        ),
        ({"expected_runtime_version": "agent-runtime-0.3.0"}, "manifest_runtime_version_mismatch"),
        ({"expected_source_revision": "d" * 40}, "manifest_source_revision_mismatch"),
    ],
)
def test_reviewed_provenance_expectations_are_enforced(
    overrides: dict[str, str],
    code: str,
) -> None:
    report = _report()
    manifest = _manifest(report)
    kwargs = {
        "expected_scenario_suite_sha256": SCENARIO_SUITE_SHA256,
        "expected_evaluation_evidence_sha256": EVALUATION_EVIDENCE_SHA256,
        "expected_runtime_version": RUNTIME_VERSION,
        "expected_source_revision": SOURCE_REVISION,
    }
    kwargs.update(overrides)

    with pytest.raises(RuntimeBenchmarkManifestError, match=code):
        verify_runtime_benchmark_manifest(
            report,
            manifest,
            **kwargs,
            keyring={KEY_ID: SECRET},
        )


def test_loader_rejects_duplicates_noncanonical_json_and_unknown_fields() -> None:
    canonical = dump_runtime_benchmark_manifest(_manifest())
    duplicate = canonical.replace('"key_id":', '"key_id":"duplicate","key_id":', 1)
    noncanonical = json.dumps(json.loads(canonical), indent=2, sort_keys=True)
    unknown = canonical[:-1] + ',"unexpected":true}'

    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_duplicate_field"):
        load_runtime_benchmark_manifest(duplicate)
    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_noncanonical"):
        load_runtime_benchmark_manifest(noncanonical)
    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_schema_invalid"):
        load_runtime_benchmark_manifest(unknown)


def test_loader_rejects_nonfinite_and_oversized_documents() -> None:
    canonical = dump_runtime_benchmark_manifest(_manifest())
    nonfinite = canonical.replace('"planned_actions":1', '"planned_actions":NaN')
    huge_integer = '{"value":' + "1" * 5_000 + "}"
    deeply_nested = "[" * 10_000 + "]" * 10_000

    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_json_invalid"):
        load_runtime_benchmark_manifest(nonfinite)
    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_json_invalid"):
        load_runtime_benchmark_manifest(huge_integer)
    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_json_invalid"):
        load_runtime_benchmark_manifest(deeply_nested)
    with pytest.raises(RuntimeBenchmarkManifestError, match="manifest_too_large"):
        load_runtime_benchmark_manifest(" " * (MAX_MANIFEST_BYTES + 1))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scenario_suite_sha256": "not-a-digest"},
        {"evaluation_evidence_sha256": "not-a-digest"},
        {"runtime_version": "unsafe version"},
        {"source_revision": "not-a-revision"},
        {"key_id": "unsafe key"},
        {"secret": b"too-short"},
    ],
)
def test_signer_rejects_malformed_provenance_or_weak_keys(kwargs: dict[str, object]) -> None:
    arguments: dict[str, object] = {
        "scenario_suite_sha256": SCENARIO_SUITE_SHA256,
        "evaluation_evidence_sha256": EVALUATION_EVIDENCE_SHA256,
        "runtime_version": RUNTIME_VERSION,
        "source_revision": SOURCE_REVISION,
        "key_id": KEY_ID,
        "secret": SECRET,
    }
    arguments.update(kwargs)

    with pytest.raises(ValueError):
        sign_runtime_benchmark_manifest(_report(), **arguments)  # type: ignore[arg-type]


def test_verifier_bounds_keyring_and_validates_expected_identifiers() -> None:
    report = _report()
    manifest = _manifest(report)

    with pytest.raises(ValueError, match="between 1 and 16"):
        _verify(
            report,
            manifest,
            keyring={f"key-{index}": SECRET for index in range(MAX_KEYRING_KEYS + 1)},
        )
    with pytest.raises(ValueError, match="safe identifier"):
        verify_runtime_benchmark_manifest(
            report,
            manifest,
            expected_scenario_suite_sha256=SCENARIO_SUITE_SHA256,
            expected_evaluation_evidence_sha256=EVALUATION_EVIDENCE_SHA256,
            expected_runtime_version="unsafe version",
            expected_source_revision=SOURCE_REVISION,
            keyring={KEY_ID: SECRET},
        )
