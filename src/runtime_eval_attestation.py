from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.runtime_eval_manifest import (
    MAX_MANIFEST_BYTES,
    RuntimeBenchmarkManifest,
    load_runtime_benchmark_manifest,
)

ATTESTATION_RECEIPT_SCHEMA = "runtime-benchmark-attestation-verification/v1"
MAX_VERIFIER_OUTPUT_BYTES = 1024 * 1024

_DIGEST = re.compile(r"[0-9a-f]{64}")
_GIT_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_REPOSITORY_ID = re.compile(r"[1-9][0-9]{0,19}")
_SOURCE_REF = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
_WORKFLOW_PATH = re.compile(r"[.]github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}[.]ya?ml")


class RuntimeBenchmarkAttestationError(RuntimeError):
    """The benchmark artifact or its independent provenance was not trusted."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RuntimeBenchmarkAttestationPolicy:
    """Immutable GitHub provenance expected by the benchmark intake boundary."""

    repository: str
    signer_workflow: str
    signer_digest: str
    source_ref: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.repository, str)
            or _REPOSITORY.fullmatch(self.repository) is None
            or not isinstance(self.signer_workflow, str)
            or _WORKFLOW_PATH.fullmatch(self.signer_workflow) is None
            or not isinstance(self.signer_digest, str)
            or _GIT_OBJECT_ID.fullmatch(self.signer_digest) is None
            or not isinstance(self.source_ref, str)
            or _SOURCE_REF.fullmatch(self.source_ref) is None
            or ".." in self.signer_workflow
            or ".." in self.source_ref
            or "//" in self.source_ref
        ):
            raise ValueError("runtime benchmark attestation policy is invalid")

    @property
    def signer_identity(self) -> str:
        return f"{self.repository}/{self.signer_workflow}"

    def commitment(self, repository_id: str | None) -> str:
        document = {
            "deny_self_hosted_runners": True,
            "repository_sha256": _sha256(self.repository),
            "signer_digest_sha256": _sha256(self.signer_digest),
            "signer_workflow_sha256": _sha256(self.signer_identity),
            "source_ref_sha256": _sha256(self.source_ref),
        }
        if repository_id is not None:
            document["repository_id_sha256"] = _sha256(repository_id)
        return hashlib.sha256(_canonical(document)).hexdigest()


def verify_runtime_benchmark_attestation(
    manifest_path: Path,
    *,
    expected_manifest_sha256: str,
    policy: RuntimeBenchmarkAttestationPolicy,
    bundle: Path | None = None,
    trusted_root: Path | None = None,
    repository_id: str | None = None,
    gh_executable: str = "gh",
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Verify one immutable manifest snapshot and its GitHub artifact provenance."""
    if not isinstance(policy, RuntimeBenchmarkAttestationPolicy):
        raise TypeError("policy must be a RuntimeBenchmarkAttestationPolicy")
    if not isinstance(expected_manifest_sha256, str) or _DIGEST.fullmatch(expected_manifest_sha256) is None:
        raise ValueError("expected manifest SHA-256 is invalid")
    if (
        not isinstance(gh_executable, str)
        or not gh_executable
        or any(character.isspace() for character in gh_executable)
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 60
    ):
        raise ValueError("attestation verifier execution policy is invalid")

    offline_arguments = (bundle, trusted_root, repository_id)
    offline = all(value is not None for value in offline_arguments)
    if any(value is not None for value in offline_arguments) != offline:
        raise ValueError("offline attestation policy must be complete")
    if repository_id is not None and (
        not isinstance(repository_id, str) or _REPOSITORY_ID.fullmatch(repository_id) is None
    ):
        raise ValueError("repository ID is invalid")

    payload = _read_manifest(manifest_path)
    manifest = _load_manifest(payload)
    if manifest.sha256 != expected_manifest_sha256:
        raise RuntimeBenchmarkAttestationError("manifest_commitment_mismatch")

    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / manifest_path.name
        snapshot.write_bytes(payload)
        os.chmod(snapshot, 0o600)
        command = [
            gh_executable,
            "attestation",
            "verify",
            str(snapshot),
            "--repo",
            policy.repository,
            "--signer-workflow",
            policy.signer_identity,
            "--signer-digest",
            policy.signer_digest,
            "--source-ref",
            policy.source_ref,
            "--deny-self-hosted-runners",
        ]
        if offline:
            command.extend(
                [
                    "--bundle",
                    str(bundle),
                    "--custom-trusted-root",
                    str(trusted_root),
                    "--format",
                    "json",
                ]
            )
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeBenchmarkAttestationError("attestation_verification_timeout") from exc
        except OSError as exc:
            raise RuntimeBenchmarkAttestationError("attestation_verifier_unavailable") from exc
    if completed.returncode != 0:
        raise RuntimeBenchmarkAttestationError("attestation_invalid")
    if offline:
        _verify_offline_repository_id(completed.stdout, repository_id)

    receipt: dict[str, Any] = {
        "attestation_policy_sha256": policy.commitment(repository_id),
        "manifest_sha256": manifest.sha256,
        "provenance_verified": True,
        "schema_version": ATTESTATION_RECEIPT_SCHEMA,
        "status": "pass",
        "verification_mode": "offline" if offline else "online",
    }
    receipt["evidence_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt


def _read_manifest(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= MAX_MANIFEST_BYTES:
            raise RuntimeBenchmarkAttestationError("manifest_file_invalid")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 8_192):
            size += len(chunk)
            if size > MAX_MANIFEST_BYTES:
                raise RuntimeBenchmarkAttestationError("manifest_file_invalid")
            chunks.append(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size:
            raise RuntimeBenchmarkAttestationError("manifest_changed_during_read")
        return payload
    except OSError as exc:
        raise RuntimeBenchmarkAttestationError("manifest_file_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_manifest(payload: bytes) -> RuntimeBenchmarkManifest:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeBenchmarkAttestationError("manifest_encoding_invalid") from exc
    try:
        return load_runtime_benchmark_manifest(text)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise RuntimeBenchmarkAttestationError("manifest_invalid") from exc


def _verify_offline_repository_id(output: str, repository_id: str | None) -> None:
    if len(output.encode("utf-8")) > MAX_VERIFIER_OUTPUT_BYTES:
        raise RuntimeBenchmarkAttestationError("attestation_result_invalid")
    try:
        results = json.loads(output)
        identifiers = [
            result["verificationResult"]["signature"]["certificate"]["sourceRepositoryIdentifier"]
            for result in results
        ]
    except (AttributeError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeBenchmarkAttestationError("attestation_result_invalid") from exc
    if not 1 <= len(identifiers) <= 16 or any(
        isinstance(value, bool) or str(value) != repository_id for value in identifiers
    ):
        raise RuntimeBenchmarkAttestationError("attestation_repository_id_invalid")


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
