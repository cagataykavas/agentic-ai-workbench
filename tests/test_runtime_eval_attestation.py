from __future__ import annotations

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from src.governed_runtime import (
    ActionResult,
    ActionStatus,
    Decision,
    ExecutionTrace,
    PolicyResult,
)
from src.runtime_eval import RuntimeGatePolicy, evaluate_traces
from src.runtime_eval_attestation import (
    ATTESTATION_RECEIPT_SCHEMA,
    RuntimeBenchmarkAttestationError,
    RuntimeBenchmarkAttestationPolicy,
    verify_runtime_benchmark_attestation,
)
from src.runtime_eval_attestation_history import (
    HISTORY_ENTRY_SCHEMA,
    RuntimeBenchmarkAttestationHistoryError,
    load_attestation_history,
)
from src.runtime_eval_manifest import (
    dump_runtime_benchmark_manifest,
    sign_runtime_benchmark_manifest,
)
from tools.verify_runtime_benchmark_attestation import main

REPOSITORY = "cagataykavas/agentic-ai-workbench"
REPOSITORY_ID = "1329851199"
SIGNER_WORKFLOW = ".github/workflows/attest-runtime-benchmark.yml"
SIGNER_DIGEST = "a" * 40
SOURCE_REF = "refs/heads/main"
SECRET = b"test-only-runtime-benchmark-signing-secret"


def manifest_document() -> tuple[str, str]:
    trace = ExecutionTrace(
        task="private benchmark task",
        planned_actions=1,
        max_steps=1,
        results=[
            ActionResult(
                action_id="lookup-1",
                tool="private-tool",
                status=ActionStatus.SUCCEEDED,
                output={"private": "payload"},
                error=None,
                policy=PolicyResult(Decision.ALLOW, "private reason"),
                idempotency_key="private-key",
            )
        ],
        stopped_reason="plan_completed",
    )
    report = evaluate_traces([trace], RuntimeGatePolicy(maximum_failure_rate=0.0))
    manifest = sign_runtime_benchmark_manifest(
        report,
        scenario_suite_sha256="b" * 64,
        evaluation_evidence_sha256="c" * 64,
        runtime_version="agent-runtime-0.2.0",
        source_revision="d" * 40,
        key_id="benchmark-signing-v1",
        secret=SECRET,
    )
    return dump_runtime_benchmark_manifest(manifest), manifest.sha256


def write_manifest(path: Path) -> str:
    document, digest = manifest_document()
    path.write_text(document, encoding="ascii")
    return digest


def policy(**overrides: str) -> RuntimeBenchmarkAttestationPolicy:
    arguments = {
        "repository": REPOSITORY,
        "signer_workflow": SIGNER_WORKFLOW,
        "signer_digest": SIGNER_DIGEST,
        "source_ref": SOURCE_REF,
    }
    arguments.update(overrides)
    return RuntimeBenchmarkAttestationPolicy(**arguments)


def offline_result(repository_id: object = REPOSITORY_ID) -> str:
    return json.dumps(
        [
            {
                "verificationResult": {
                    "signature": {
                        "certificate": {
                            "sourceRepositoryIdentifier": repository_id,
                        }
                    }
                }
            }
        ]
    )


def test_online_verification_uses_immutable_snapshot_and_reduced_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "runtime-benchmark-manifest.json"
    expected = write_manifest(manifest)
    original = manifest.read_bytes()
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        snapshot = Path(command[3])
        assert snapshot != manifest
        assert snapshot.name == manifest.name
        assert snapshot.read_bytes() == original
        manifest.write_text("substituted after snapshot", encoding="utf-8")
        assert kwargs == {
            "capture_output": True,
            "check": False,
            "text": True,
            "timeout": 30,
        }
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("src.runtime_eval_attestation.subprocess.run", run)
    receipt = verify_runtime_benchmark_attestation(
        manifest,
        expected_manifest_sha256=expected,
        policy=policy(),
    )

    assert receipt["schema_version"] == ATTESTATION_RECEIPT_SCHEMA
    assert receipt["manifest_sha256"] == expected
    assert receipt["provenance_verified"] is True
    assert receipt["verification_mode"] == "online"
    assert len(receipt["attestation_policy_sha256"]) == 64
    assert len(receipt["evidence_sha256"]) == 64
    assert commands[0][0:3] == ["gh", "attestation", "verify"]
    assert commands[0][4:] == [
        "--repo",
        REPOSITORY,
        "--signer-workflow",
        f"{REPOSITORY}/{SIGNER_WORKFLOW}",
        "--signer-digest",
        SIGNER_DIGEST,
        "--source-ref",
        SOURCE_REF,
        "--deny-self-hosted-runners",
    ]
    serialized = json.dumps(receipt, sort_keys=True)
    for private_policy in (REPOSITORY, SIGNER_WORKFLOW, SOURCE_REF, REPOSITORY_ID):
        assert private_policy not in serialized


def test_offline_verification_pins_bundle_root_and_repository_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    bundle = tmp_path / "bundle.jsonl"
    trusted_root = tmp_path / "trusted-root.jsonl"
    bundle.write_text("bundle", encoding="utf-8")
    trusted_root.write_text("root", encoding="utf-8")
    observed: list[str] = []

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        observed.extend(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=offline_result(),
            stderr="",
        )

    monkeypatch.setattr("src.runtime_eval_attestation.subprocess.run", run)
    receipt = verify_runtime_benchmark_attestation(
        manifest,
        expected_manifest_sha256=expected,
        policy=policy(),
        bundle=bundle,
        trusted_root=trusted_root,
        repository_id=REPOSITORY_ID,
    )

    assert receipt["verification_mode"] == "offline"
    assert observed[-6:] == [
        "--bundle",
        str(bundle),
        "--custom-trusted-root",
        str(trusted_root),
        "--format",
        "json",
    ]


@pytest.mark.parametrize("repository_id", ["999", True, None])
def test_offline_verification_rejects_untrusted_or_malformed_results(
    repository_id: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    bundle = tmp_path / "bundle.jsonl"
    root = tmp_path / "root.jsonl"

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        stdout = "not-json" if repository_id is None else offline_result(repository_id)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr("src.runtime_eval_attestation.subprocess.run", run)
    with pytest.raises(RuntimeBenchmarkAttestationError, match="attestation_(repository_id|result)_invalid"):
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256=expected,
            policy=policy(),
            bundle=bundle,
            trusted_root=root,
            repository_id=REPOSITORY_ID,
        )


def test_rejects_manifest_substitution_noncanonical_input_and_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    monkeypatch.setattr(
        "src.runtime_eval_attestation.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("verifier must not run"),
    )

    with pytest.raises(RuntimeBenchmarkAttestationError, match="commitment_mismatch"):
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256="f" * 64,
            policy=policy(),
        )

    manifest.write_text(json.dumps(json.loads(manifest.read_text()), indent=2))
    with pytest.raises(RuntimeBenchmarkAttestationError, match="manifest_invalid"):
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256=expected,
            policy=policy(),
        )

    write_manifest(manifest)
    link = tmp_path / "manifest-link.json"
    link.symlink_to(manifest)
    with pytest.raises(RuntimeBenchmarkAttestationError, match="manifest_file_invalid"):
        verify_runtime_benchmark_attestation(
            link,
            expected_manifest_sha256=expected,
            policy=policy(),
        )


def test_rejects_incomplete_offline_policy_and_unsafe_provenance(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    with pytest.raises(ValueError, match="offline attestation policy"):
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256=expected,
            policy=policy(),
            bundle=tmp_path / "bundle.jsonl",
        )
    for overrides in (
        {"repository": "unsafe repository"},
        {"signer_workflow": "../signer.yml"},
        {"signer_digest": "not-a-digest"},
        {"source_ref": "refs/pull/1/head"},
    ):
        with pytest.raises(ValueError, match="policy is invalid"):
            policy(**overrides)


def test_verifier_failures_are_sanitized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)

    def fail(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="private provider detail",
        )

    monkeypatch.setattr("src.runtime_eval_attestation.subprocess.run", fail)
    with pytest.raises(RuntimeBenchmarkAttestationError, match="^attestation_invalid$"):
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256=expected,
            policy=policy(),
        )


def test_cli_writes_private_receipt_and_refuses_input_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    output = tmp_path / "attestation-receipt.json"
    monkeypatch.setattr(
        "src.runtime_eval_attestation.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    arguments = [
        str(manifest),
        "--expected-manifest-sha256",
        expected,
        "--repository",
        REPOSITORY,
        "--signer-workflow",
        SIGNER_WORKFLOW,
        "--signer-digest",
        SIGNER_DIGEST,
        "--source-ref",
        SOURCE_REF,
        "--output",
        str(output),
    ]

    assert main(arguments) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "pass"
    assert os.stat(output).st_mode & 0o777 == 0o600

    arguments[-1] = str(manifest)
    assert main(arguments) == 2


def test_successful_verification_appends_idempotent_private_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    history = tmp_path / "accepted-manifests.jsonl"
    monkeypatch.setattr(
        "src.runtime_eval_attestation.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    first = verify_runtime_benchmark_attestation(
        manifest,
        expected_manifest_sha256=expected,
        policy=policy(),
        acceptance_history=history,
    )
    second = verify_runtime_benchmark_attestation(
        manifest,
        expected_manifest_sha256=expected,
        policy=policy(),
        acceptance_history=history,
    )

    assert first == second
    entries = load_attestation_history(history)
    assert len(entries) == 1
    assert entries[0] == {
        "attestation_policy_sha256": first["attestation_policy_sha256"],
        "entry_sha256": entries[0]["entry_sha256"],
        "manifest_sha256": expected,
        "previous_entry_sha256": "0" * 64,
        "receipt_evidence_sha256": first["evidence_sha256"],
        "schema_version": HISTORY_ENTRY_SCHEMA,
        "sequence": 1,
        "verification_mode": "online",
    }
    assert os.stat(history).st_mode & 0o777 == 0o600
    retained = history.read_text(encoding="ascii")
    for private_policy in (REPOSITORY, SIGNER_WORKFLOW, SOURCE_REF, REPOSITORY_ID):
        assert private_policy not in retained


def test_history_chains_distinct_acceptances_and_detects_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    history = tmp_path / "accepted-manifests.jsonl"
    monkeypatch.setattr(
        "src.runtime_eval_attestation.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    for digest in ("a" * 40, "b" * 40):
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256=expected,
            policy=policy(signer_digest=digest),
            acceptance_history=history,
        )

    entries = load_attestation_history(history)
    assert [entry["sequence"] for entry in entries] == [1, 2]
    assert entries[1]["previous_entry_sha256"] == entries[0]["entry_sha256"]

    history.write_bytes(history.read_bytes().splitlines(keepends=True)[1])
    with pytest.raises(RuntimeBenchmarkAttestationHistoryError, match="chain_invalid"):
        load_attestation_history(history)


def test_history_serializes_concurrent_verified_acceptances(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    history = tmp_path / "accepted-manifests.jsonl"
    monkeypatch.setattr(
        "src.runtime_eval_attestation.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    def verify(index: int) -> None:
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256=expected,
            policy=policy(signer_digest=f"{index:040x}"),
            acceptance_history=history,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(verify, range(1, 9)))

    entries = load_attestation_history(history)
    assert [entry["sequence"] for entry in entries] == list(range(1, 9))
    assert len({entry["receipt_evidence_sha256"] for entry in entries}) == 8


def test_failed_attestation_never_creates_acceptance_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    history = tmp_path / "accepted-manifests.jsonl"
    monkeypatch.setattr(
        "src.runtime_eval_attestation.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 1, stdout="", stderr="provider detail"
        ),
    )

    with pytest.raises(RuntimeBenchmarkAttestationError, match="^attestation_invalid$"):
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256=expected,
            policy=policy(),
            acceptance_history=history,
        )

    assert not history.exists()


def test_history_fails_closed_for_tampering_symlinks_and_weak_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    history = tmp_path / "accepted-manifests.jsonl"
    monkeypatch.setattr(
        "src.runtime_eval_attestation.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    verify_runtime_benchmark_attestation(
        manifest,
        expected_manifest_sha256=expected,
        policy=policy(),
        acceptance_history=history,
    )

    document = json.loads(history.read_text(encoding="ascii"))
    document["manifest_sha256"] = "f" * 64
    history.write_text(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n")
    with pytest.raises(RuntimeBenchmarkAttestationHistoryError, match="chain_invalid"):
        load_attestation_history(history)

    history.chmod(0o644)
    with pytest.raises(RuntimeBenchmarkAttestationHistoryError, match="file_unsafe"):
        load_attestation_history(history)

    target = tmp_path / "target.jsonl"
    target.write_text("", encoding="ascii")
    target.chmod(0o600)
    link = tmp_path / "history-link.jsonl"
    link.symlink_to(target)
    with pytest.raises(RuntimeBenchmarkAttestationHistoryError, match="unavailable"):
        verify_runtime_benchmark_attestation(
            manifest,
            expected_manifest_sha256=expected,
            policy=policy(),
            acceptance_history=link,
        )


def test_cli_refuses_receipt_history_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    expected = write_manifest(manifest)
    output = tmp_path / "evidence.json"
    monkeypatch.setattr(
        "src.runtime_eval_attestation.subprocess.run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )
    arguments = [
        str(manifest),
        "--expected-manifest-sha256",
        expected,
        "--repository",
        REPOSITORY,
        "--signer-workflow",
        SIGNER_WORKFLOW,
        "--signer-digest",
        SIGNER_DIGEST,
        "--source-ref",
        SOURCE_REF,
        "--output",
        str(output),
        "--acceptance-history",
        str(output),
    ]

    assert main(arguments) == 2
    assert not output.exists()
