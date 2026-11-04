from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from src.governed_runtime import ExecutionTrace
from src.runtime_eval import (
    MAX_EVALUATION_ACTIONS,
    MAX_EVALUATION_TRACES,
    RuntimeEvaluationError,
    RuntimeGatePolicy,
    RuntimeGateReport,
    evaluate_traces,
)

SCHEMA_VERSION = "runtime-benchmark-manifest/v2"
MAX_MANIFEST_BYTES = 32_768
MAX_KEYRING_KEYS = 16
_MANIFEST_FIELDS = frozenset(
    {
        "key_id",
        "evaluation_evidence_sha256",
        "planned_actions",
        "policy_sha256",
        "report_sha256",
        "runtime_version",
        "scenario_suite_sha256",
        "schema_version",
        "signature",
        "source_revision",
        "trace_count",
    }
)
_DOMAIN = b"agentic-ai-runtime-benchmark-manifest-v2\0"
_REPORT_DOMAIN = b"agentic-ai-runtime-gate-report-v1\0"
_EVIDENCE_DOMAIN = b"agentic-ai-runtime-evaluation-evidence-v1\0"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SOURCE_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}")


class RuntimeBenchmarkManifestError(RuntimeError):
    """The manifest could not authenticate the benchmark gate result."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RuntimeBenchmarkManifest:
    """Authenticated, privacy-reduced provenance for one aggregate gate report."""

    schema_version: str
    scenario_suite_sha256: str
    evaluation_evidence_sha256: str
    runtime_version: str
    source_revision: str
    policy_sha256: str
    report_sha256: str
    trace_count: int
    planned_actions: int
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("schema_version is unsupported")
        _require_sha256(self.scenario_suite_sha256, "scenario_suite_sha256")
        _require_sha256(self.evaluation_evidence_sha256, "evaluation_evidence_sha256")
        _require_identifier(self.runtime_version, "runtime_version")
        if (
            not isinstance(self.source_revision, str)
            or _SOURCE_REVISION.fullmatch(self.source_revision) is None
        ):
            raise ValueError("source_revision must be a lowercase Git object ID")
        _require_sha256(self.policy_sha256, "policy_sha256")
        _require_sha256(self.report_sha256, "report_sha256")
        _require_bounded_integer(
            self.trace_count,
            "trace_count",
            minimum=1,
            maximum=MAX_EVALUATION_TRACES,
        )
        _require_bounded_integer(
            self.planned_actions,
            "planned_actions",
            minimum=0,
            maximum=MAX_EVALUATION_ACTIONS,
        )
        _require_identifier(self.key_id, "key_id")
        _require_sha256(self.signature, "signature")

    def unsigned_document(self) -> dict[str, str | int]:
        return {
            "key_id": self.key_id,
            "evaluation_evidence_sha256": self.evaluation_evidence_sha256,
            "planned_actions": self.planned_actions,
            "policy_sha256": self.policy_sha256,
            "report_sha256": self.report_sha256,
            "runtime_version": self.runtime_version,
            "scenario_suite_sha256": self.scenario_suite_sha256,
            "schema_version": self.schema_version,
            "source_revision": self.source_revision,
            "trace_count": self.trace_count,
        }

    def document(self) -> dict[str, str | int]:
        return {**self.unsigned_document(), "signature": self.signature}

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical(self.document())).hexdigest()


def sign_runtime_benchmark_manifest(
    report: RuntimeGateReport,
    *,
    scenario_suite_sha256: str,
    evaluation_evidence_sha256: str,
    runtime_version: str,
    source_revision: str,
    key_id: str,
    secret: bytes,
) -> RuntimeBenchmarkManifest:
    """Bind one aggregate report to reviewed benchmark provenance."""
    _require_report(report)
    _require_secret(secret, "signing secret")
    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "scenario_suite_sha256": scenario_suite_sha256,
        "evaluation_evidence_sha256": evaluation_evidence_sha256,
        "runtime_version": runtime_version,
        "source_revision": source_revision,
        "policy_sha256": report.policy_sha256,
        "report_sha256": _report_sha256(report),
        "trace_count": report.metrics.trace_count,
        "planned_actions": report.metrics.planned_actions,
        "key_id": key_id,
    }
    placeholder = RuntimeBenchmarkManifest(**unsigned, signature="0" * 64)
    signature = hmac.new(
        secret,
        _DOMAIN + _canonical(placeholder.unsigned_document()),
        hashlib.sha256,
    ).hexdigest()
    return replace(placeholder, signature=signature)


def verify_runtime_benchmark_manifest(
    report: RuntimeGateReport,
    manifest: RuntimeBenchmarkManifest,
    *,
    expected_scenario_suite_sha256: str,
    expected_evaluation_evidence_sha256: str,
    expected_runtime_version: str,
    expected_source_revision: str,
    keyring: Mapping[str, bytes],
) -> str:
    """Verify provenance and return the canonical manifest commitment."""
    _require_report(report)
    if not isinstance(manifest, RuntimeBenchmarkManifest):
        raise TypeError("manifest must be a RuntimeBenchmarkManifest")
    keys = _validated_keyring(keyring)
    _require_identifier(expected_runtime_version, "expected_runtime_version")
    if (
        not isinstance(expected_source_revision, str)
        or _SOURCE_REVISION.fullmatch(expected_source_revision) is None
    ):
        raise ValueError("expected_source_revision must be a lowercase Git object ID")
    secret = keys.get(manifest.key_id)
    if secret is None:
        raise RuntimeBenchmarkManifestError("manifest_key_unknown")
    expected_signature = hmac.new(
        secret,
        _DOMAIN + _canonical(manifest.unsigned_document()),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, manifest.signature):
        raise RuntimeBenchmarkManifestError("manifest_signature_invalid")
    if not hmac.compare_digest(
        manifest.scenario_suite_sha256,
        _validated_sha256(expected_scenario_suite_sha256, "expected scenario suite"),
    ):
        raise RuntimeBenchmarkManifestError("manifest_scenario_suite_mismatch")
    if not hmac.compare_digest(
        manifest.evaluation_evidence_sha256,
        _validated_sha256(expected_evaluation_evidence_sha256, "expected evaluation evidence"),
    ):
        raise RuntimeBenchmarkManifestError("manifest_evaluation_evidence_mismatch")
    if manifest.runtime_version != expected_runtime_version:
        raise RuntimeBenchmarkManifestError("manifest_runtime_version_mismatch")
    if manifest.source_revision != expected_source_revision:
        raise RuntimeBenchmarkManifestError("manifest_source_revision_mismatch")
    if not hmac.compare_digest(manifest.policy_sha256, report.policy_sha256):
        raise RuntimeBenchmarkManifestError("manifest_policy_mismatch")
    if manifest.trace_count != report.metrics.trace_count:
        raise RuntimeBenchmarkManifestError("manifest_trace_count_mismatch")
    if manifest.planned_actions != report.metrics.planned_actions:
        raise RuntimeBenchmarkManifestError("manifest_action_count_mismatch")
    if not hmac.compare_digest(manifest.report_sha256, _report_sha256(report)):
        raise RuntimeBenchmarkManifestError("manifest_report_mismatch")
    return manifest.sha256


def runtime_evaluation_evidence_sha256(traces: Sequence[ExecutionTrace]) -> str:
    """Commit to gate-relevant trace evidence without retaining private payload values."""
    evaluate_traces(traces, RuntimeGatePolicy())
    hasher = hashlib.sha256(_EVIDENCE_DOMAIN)
    _update_evidence_digest(hasher, {"trace_count": len(traces)})
    for trace in traces:
        _update_evidence_digest(
            hasher,
            {
                "max_steps": trace.max_steps,
                "planned_actions": trace.planned_actions,
                "result_count": len(trace.results),
                "stopped_reason": trace.stopped_reason,
            },
        )
        for result in trace.results:
            _update_evidence_digest(
                hasher,
                {
                    "action_id": result.action_id,
                    "error_kind": "text" if result.error is not None else "none",
                    "output_kind": "mapping" if result.output is not None else "none",
                    "policy_decision": result.policy.decision.value,
                    "status": result.status.value,
                },
            )
    return hasher.hexdigest()


def evaluate_and_sign_runtime_benchmark(
    traces: Sequence[ExecutionTrace],
    policy: RuntimeGatePolicy,
    *,
    scenario_suite_sha256: str,
    runtime_version: str,
    source_revision: str,
    key_id: str,
    secret: bytes,
) -> tuple[RuntimeGateReport, RuntimeBenchmarkManifest]:
    """Recompute a stable trace-set report before signing its provenance."""
    evidence_before = runtime_evaluation_evidence_sha256(traces)
    report = evaluate_traces(traces, policy)
    evidence_after = runtime_evaluation_evidence_sha256(traces)
    if not hmac.compare_digest(evidence_before, evidence_after):
        raise RuntimeEvaluationError("trace_set_changed_during_evaluation")
    manifest = sign_runtime_benchmark_manifest(
        report,
        scenario_suite_sha256=scenario_suite_sha256,
        evaluation_evidence_sha256=evidence_after,
        runtime_version=runtime_version,
        source_revision=source_revision,
        key_id=key_id,
        secret=secret,
    )
    return report, manifest


def evaluate_and_verify_runtime_benchmark(
    traces: Sequence[ExecutionTrace],
    policy: RuntimeGatePolicy,
    manifest: RuntimeBenchmarkManifest,
    *,
    expected_scenario_suite_sha256: str,
    expected_runtime_version: str,
    expected_source_revision: str,
    keyring: Mapping[str, bytes],
) -> tuple[RuntimeGateReport, str]:
    """Recompute a stable trace-set report before verifying its manifest."""
    evidence_before = runtime_evaluation_evidence_sha256(traces)
    report = evaluate_traces(traces, policy)
    evidence_after = runtime_evaluation_evidence_sha256(traces)
    if not hmac.compare_digest(evidence_before, evidence_after):
        raise RuntimeEvaluationError("trace_set_changed_during_evaluation")
    commitment = verify_runtime_benchmark_manifest(
        report,
        manifest,
        expected_scenario_suite_sha256=expected_scenario_suite_sha256,
        expected_evaluation_evidence_sha256=evidence_after,
        expected_runtime_version=expected_runtime_version,
        expected_source_revision=expected_source_revision,
        keyring=keyring,
    )
    return report, commitment


def dump_runtime_benchmark_manifest(manifest: RuntimeBenchmarkManifest) -> str:
    if not isinstance(manifest, RuntimeBenchmarkManifest):
        raise TypeError("manifest must be a RuntimeBenchmarkManifest")
    return _canonical(manifest.document()).decode("ascii")


def load_runtime_benchmark_manifest(text: str) -> RuntimeBenchmarkManifest:
    if not isinstance(text, str):
        raise TypeError("manifest JSON must be text")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RuntimeBenchmarkManifestError("manifest_json_invalid") from exc
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise RuntimeBenchmarkManifestError("manifest_too_large")
    try:
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise RuntimeBenchmarkManifestError("manifest_json_invalid") from exc
    if not isinstance(document, dict) or set(document) != _MANIFEST_FIELDS:
        raise RuntimeBenchmarkManifestError("manifest_schema_invalid")
    try:
        manifest = RuntimeBenchmarkManifest(**document)
    except (TypeError, ValueError) as exc:
        raise RuntimeBenchmarkManifestError("manifest_fields_invalid") from exc
    if dump_runtime_benchmark_manifest(manifest) != text:
        raise RuntimeBenchmarkManifestError("manifest_noncanonical")
    return manifest


def _report_sha256(report: RuntimeGateReport) -> str:
    return hashlib.sha256(_REPORT_DOMAIN + _canonical(report.to_dict())).hexdigest()


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _update_evidence_digest(hasher: Any, document: Mapping[str, Any]) -> None:
    payload = _canonical(document)
    hasher.update(len(payload).to_bytes(8, "big"))
    hasher.update(payload)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise RuntimeBenchmarkManifestError("manifest_duplicate_field")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise RuntimeBenchmarkManifestError("manifest_json_invalid")


def _require_report(report: RuntimeGateReport) -> None:
    if not isinstance(report, RuntimeGateReport):
        raise TypeError("report must be a RuntimeGateReport")
    report.validate()


def _validated_keyring(keyring: Mapping[str, bytes]) -> dict[str, bytes]:
    if not isinstance(keyring, Mapping) or not 1 <= len(keyring) <= MAX_KEYRING_KEYS:
        raise ValueError("keyring must contain between 1 and 16 keys")
    copied: dict[str, bytes] = {}
    for key_id, secret in keyring.items():
        _require_identifier(key_id, "key_id")
        _require_secret(secret, "verification secret")
        copied[key_id] = secret
    return copied


def _require_secret(secret: bytes, name: str) -> None:
    if not isinstance(secret, bytes) or not 32 <= len(secret) <= 4_096:
        raise ValueError(f"{name} must contain between 32 and 4096 bytes")


def _validated_sha256(value: str, name: str) -> str:
    _require_sha256(value, name)
    return value


def _require_sha256(value: Any, name: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _require_identifier(value: Any, name: str) -> None:
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe identifier")


def _require_bounded_integer(value: Any, name: str, *, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
