from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

import src.reviewed_runtime_benchmark as benchmark_module
from src.governed_runtime import ActionStatus
from src.reviewed_runtime_benchmark import (
    REVIEWED_SCENARIOS,
    RUNTIME_VERSION,
    ReviewedRuntimeBenchmarkError,
    reviewed_scenario_suite_sha256,
    run_reviewed_runtime_benchmark,
    sign_reviewed_runtime_benchmark,
)
from src.runtime_eval import evaluate_traces
from src.runtime_eval_manifest import (
    dump_runtime_benchmark_manifest,
    evaluate_and_verify_runtime_benchmark,
    load_runtime_benchmark_manifest,
)
from tools.sign_reviewed_runtime_benchmark import main

SOURCE_REVISION = "a" * 40
KEY_ID = "runtime-benchmark-signing-v1"
SECRET = b"test-only-runtime-benchmark-signing-secret-v1"


def test_reviewed_suite_executes_real_runtime_boundaries_and_passes_gate() -> None:
    traces, policy = run_reviewed_runtime_benchmark()
    report = evaluate_traces(traces, policy)

    assert report.passed
    assert report.metrics.trace_count == 8
    assert report.metrics.planned_actions == 12
    assert report.metrics.succeeded_actions == 5
    assert report.metrics.failed_actions == 1
    assert report.metrics.awaiting_approval_actions == 1
    assert report.metrics.denied_actions == 2
    assert report.metrics.replayed_actions == 1
    assert report.metrics.budget_skipped_actions == 2
    assert report.metrics.completed_trace_rate == 7 / 8
    assert [result.status for result in traces[5].results] == [
        ActionStatus.SUCCEEDED,
        ActionStatus.REPLAYED,
    ]


def test_signed_manifest_is_recomputed_and_verifiable_from_reviewed_suite() -> None:
    report, manifest = sign_reviewed_runtime_benchmark(
        source_revision=SOURCE_REVISION,
        key_id=KEY_ID,
        secret=SECRET,
    )
    traces, policy = run_reviewed_runtime_benchmark()
    verified_report, commitment = evaluate_and_verify_runtime_benchmark(
        traces,
        policy,
        manifest,
        expected_scenario_suite_sha256=reviewed_scenario_suite_sha256(),
        expected_runtime_version=RUNTIME_VERSION,
        expected_source_revision=SOURCE_REVISION,
        keyring={KEY_ID: SECRET},
    )

    assert report == verified_report
    assert commitment == manifest.sha256
    assert manifest.trace_count == len(REVIEWED_SCENARIOS)
    assert load_runtime_benchmark_manifest(dump_runtime_benchmark_manifest(manifest)) == manifest


def test_manifest_and_suite_commitment_exclude_private_runtime_values() -> None:
    _, manifest = sign_reviewed_runtime_benchmark(
        source_revision=SOURCE_REVISION,
        key_id=KEY_ID,
        secret=SECRET,
    )
    serialized = dump_runtime_benchmark_manifest(manifest)

    for private_value in (
        "lookup",
        "publish",
        "unstable",
        "reviewed-replay-key",
        "controlled benchmark failure",
        "reviewed-scenario",
    ):
        assert private_value not in serialized
    assert len(reviewed_scenario_suite_sha256()) == 64


def test_suite_refuses_observed_behavior_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    changed = replace(
        REVIEWED_SCENARIOS[0],
        expected_statuses=(ActionStatus.FAILED, ActionStatus.SUCCEEDED),
    )
    monkeypatch.setattr(
        benchmark_module,
        "REVIEWED_SCENARIOS",
        (changed, *REVIEWED_SCENARIOS[1:]),
    )

    with pytest.raises(ReviewedRuntimeBenchmarkError, match="outcome drifted"):
        run_reviewed_runtime_benchmark()


def test_cli_writes_new_private_canonical_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "runtime-benchmark-manifest.json"
    monkeypatch.setenv("RUNTIME_BENCHMARK_SIGNING_SECRET", SECRET.decode())
    arguments = [
        "--source-revision",
        SOURCE_REVISION,
        "--key-id",
        KEY_ID,
        "--output",
        str(output),
    ]

    assert main(arguments) == 0
    manifest = load_runtime_benchmark_manifest(output.read_text(encoding="ascii"))
    assert manifest.source_revision == SOURCE_REVISION
    assert manifest.scenario_suite_sha256 == reviewed_scenario_suite_sha256()
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert main(arguments) == 2


def test_cli_fails_closed_without_secret_or_with_invalid_source_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "manifest.json"
    monkeypatch.delenv("RUNTIME_BENCHMARK_SIGNING_SECRET", raising=False)
    assert main(["--source-revision", SOURCE_REVISION, "--output", str(output)]) == 2
    assert not output.exists()

    monkeypatch.setenv("RUNTIME_BENCHMARK_SIGNING_SECRET", SECRET.decode())
    assert main(["--source-revision", "mutable", "--output", str(output)]) == 2
    assert not output.exists()


def test_cli_receipt_is_aggregate_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("RUNTIME_BENCHMARK_SIGNING_SECRET", SECRET.decode())
    assert (
        main(
            [
                "--source-revision",
                SOURCE_REVISION,
                "--output",
                str(tmp_path / "manifest.json"),
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["status"] == "pass"
    assert receipt["trace_count"] == 8
    assert receipt["planned_actions"] == 12
    assert SECRET.decode() not in json.dumps(receipt)
