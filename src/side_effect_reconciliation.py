from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class ArtifactMalformed(ValueError):
    """The evidence artifact is unsafe or does not match the contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class EffectKind(str, Enum):
    NONE = "none"
    IDEMPOTENT = "idempotent"
    COMPENSATABLE = "compensatable"
    IRREVERSIBLE = "irreversible"


class RuntimeState(str, Enum):
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ReceiptStatus(str, Enum):
    COMMITTED = "committed"
    REJECTED = "rejected"
    COMPENSATED = "compensated"


class Action(str, Enum):
    WAIT = "wait"
    MARK_SUCCEEDED = "mark_succeeded"
    MARK_FAILED = "mark_failed"
    RETRY_SAME_KEY = "retry_same_key"
    RETRY_READ = "retry_read"
    COMPENSATE = "compensate"
    QUERY_THEN_ESCALATE = "query_then_escalate"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class ReconciliationPolicy:
    max_input_bytes: int = 262_144
    max_calls: int = 1_000
    max_receipts_per_call: int = 16
    max_evidence_age_seconds: int = 86_400
    max_future_skew_seconds: int = 60

    def __post_init__(self) -> None:
        if not 1 <= self.max_input_bytes <= 8_388_608:
            raise ValueError("max_input_bytes outside supported range")
        if not 1 <= self.max_calls <= 10_000:
            raise ValueError("max_calls outside supported range")
        if not 1 <= self.max_receipts_per_call <= 100:
            raise ValueError("max_receipts_per_call outside supported range")
        if not 1 <= self.max_evidence_age_seconds <= 604_800:
            raise ValueError("max_evidence_age_seconds outside supported range")
        if not 0 <= self.max_future_skew_seconds <= 3_600:
            raise ValueError("max_future_skew_seconds outside supported range")


@dataclass(frozen=True)
class Finding:
    call_sha256: str
    code: str
    action: str


@dataclass(frozen=True)
class ReconciliationReport:
    schema_version: int
    status: str
    accepted: bool
    artifact_sha256: str
    policy_sha256: str
    call_count: int
    receipt_count: int
    finding_count: int
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [asdict(finding) for finding in self.findings]
        return data


def _reject_constant(_value: str) -> None:
    raise ArtifactMalformed("NON_FINITE_NUMBER")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactMalformed("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def load_artifact(raw: bytes, policy: ReconciliationPolicy) -> dict[str, Any]:
    if len(raw) > policy.max_input_bytes:
        raise ArtifactMalformed("INPUT_TOO_LARGE")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactMalformed("INVALID_UTF8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ArtifactMalformed:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ArtifactMalformed("INVALID_JSON") from exc
    if not isinstance(value, dict):
        raise ArtifactMalformed("ROOT_NOT_OBJECT")
    return value


def audit_artifact(
    artifact: dict[str, Any],
    *,
    as_of: datetime,
    policy: ReconciliationPolicy | None = None,
) -> ReconciliationReport:
    selected_policy = policy or ReconciliationPolicy()
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("as_of must be timezone-aware")
    as_of = as_of.astimezone(UTC)

    _expect_keys(
        artifact,
        {"schema_version", "run_id", "policy_id", "observed_at", "calls"},
        "ROOT_FIELDS",
    )
    if artifact["schema_version"] != 1 or isinstance(artifact["schema_version"], bool):
        raise ArtifactMalformed("SCHEMA_VERSION")
    _identifier(artifact["run_id"], "RUN_ID")
    _identifier(artifact["policy_id"], "POLICY_ID")
    observed_at = _timestamp(artifact["observed_at"], "OBSERVED_AT")
    if observed_at > as_of + timedelta(seconds=selected_policy.max_future_skew_seconds):
        raise ArtifactMalformed("EVIDENCE_FROM_FUTURE")
    if as_of - observed_at > timedelta(seconds=selected_policy.max_evidence_age_seconds):
        raise ArtifactMalformed("STALE_EVIDENCE")

    calls = artifact["calls"]
    if not isinstance(calls, list) or not calls:
        raise ArtifactMalformed("CALLS_REQUIRED")
    if len(calls) > selected_policy.max_calls:
        raise ArtifactMalformed("CALL_BUDGET_EXCEEDED")

    seen_calls: set[str] = set()
    seen_receipts: set[str] = set()
    findings: list[Finding] = []
    receipt_count = 0
    for call in calls:
        call_findings, call_receipt_count = _audit_call(
            call,
            observed_at=observed_at,
            seen_calls=seen_calls,
            seen_receipts=seen_receipts,
            policy=selected_policy,
        )
        findings.extend(call_findings)
        receipt_count += call_receipt_count

    findings.sort(key=lambda item: (item.call_sha256, item.code, item.action))
    canonical_artifact = _canonical_json(artifact)
    policy_payload = asdict(selected_policy)
    return ReconciliationReport(
        schema_version=1,
        status="clean" if not findings else "reconciliation_required",
        accepted=not findings,
        artifact_sha256=_sha256(canonical_artifact),
        policy_sha256=_sha256(_canonical_json(policy_payload)),
        call_count=len(calls),
        receipt_count=receipt_count,
        finding_count=len(findings),
        findings=tuple(findings),
    )


def _audit_call(
    call: Any,
    *,
    observed_at: datetime,
    seen_calls: set[str],
    seen_receipts: set[str],
    policy: ReconciliationPolicy,
) -> tuple[list[Finding], int]:
    if not isinstance(call, dict):
        raise ArtifactMalformed("CALL_NOT_OBJECT")
    _expect_keys(
        call,
        {
            "call_id",
            "tool",
            "intent_sha256",
            "idempotency_key_sha256",
            "effect_kind",
            "runtime_state",
            "started_at",
            "finished_at",
            "lease_expires_at",
            "receipts",
        },
        "CALL_FIELDS",
    )
    call_id = _identifier(call["call_id"], "CALL_ID")
    if call_id in seen_calls:
        raise ArtifactMalformed("DUPLICATE_CALL_ID")
    seen_calls.add(call_id)
    _identifier(call["tool"], "TOOL")
    intent_sha256 = _digest(call["intent_sha256"], "INTENT_SHA256")
    idempotency_key = _optional_digest(call["idempotency_key_sha256"], "IDEMPOTENCY_KEY_SHA256")
    effect_kind = _enum(EffectKind, call["effect_kind"], "EFFECT_KIND")
    runtime_state = _enum(RuntimeState, call["runtime_state"], "RUNTIME_STATE")
    started_at = _timestamp(call["started_at"], "STARTED_AT")
    finished_at = _optional_timestamp(call["finished_at"], "FINISHED_AT")
    lease_expires_at = _timestamp(call["lease_expires_at"], "LEASE_EXPIRES_AT")

    if started_at > observed_at or lease_expires_at < started_at:
        raise ArtifactMalformed("CALL_TIME_ORDER")
    if finished_at is not None and not started_at <= finished_at <= observed_at:
        raise ArtifactMalformed("CALL_TIME_ORDER")
    if runtime_state in {RuntimeState.SUCCEEDED, RuntimeState.FAILED} and finished_at is None:
        raise ArtifactMalformed("TERMINAL_STATE_WITHOUT_FINISH")
    if runtime_state is RuntimeState.EXECUTING and finished_at is not None:
        raise ArtifactMalformed("EXECUTING_STATE_WITH_FINISH")
    if effect_kind is not EffectKind.NONE and idempotency_key is None:
        raise ArtifactMalformed("WRITE_WITHOUT_IDEMPOTENCY_KEY")

    receipts = call["receipts"]
    if not isinstance(receipts, list):
        raise ArtifactMalformed("RECEIPTS_NOT_ARRAY")
    if len(receipts) > policy.max_receipts_per_call:
        raise ArtifactMalformed("RECEIPT_BUDGET_EXCEEDED")

    committed: dict[str, datetime] = {}
    compensated: set[str] = set()
    rejected_count = 0
    for receipt in receipts:
        parsed = _parse_receipt(
            receipt,
            call_intent=intent_sha256,
            call_idempotency_key=idempotency_key,
            started_at=started_at,
            observed_at=observed_at,
            seen_receipts=seen_receipts,
        )
        if parsed["status"] is ReceiptStatus.COMMITTED:
            operation = parsed["operation_sha256"]
            if operation in committed:
                raise ArtifactMalformed("DUPLICATE_COMMIT_RECEIPT")
            committed[operation] = parsed["observed_at"]
        elif parsed["status"] is ReceiptStatus.COMPENSATED:
            if effect_kind is not EffectKind.COMPENSATABLE:
                raise ArtifactMalformed("COMPENSATION_FOR_NON_COMPENSATABLE_EFFECT")
            target = parsed["compensates_operation_sha256"]
            if target in compensated:
                raise ArtifactMalformed("DUPLICATE_COMPENSATION")
            compensated.add(target)
        else:
            rejected_count += 1

    for receipt in receipts:
        if receipt["status"] != ReceiptStatus.COMPENSATED.value:
            continue
        target = receipt["compensates_operation_sha256"]
        compensation_time = _timestamp(receipt["observed_at"], "RECEIPT_OBSERVED_AT")
        if target not in committed:
            raise ArtifactMalformed("ORPHAN_COMPENSATION")
        if compensation_time < committed[target]:
            raise ArtifactMalformed("COMPENSATION_BEFORE_COMMIT")

    call_hash = _sha256(call_id.encode())
    active_commits = set(committed) - compensated
    result: list[Finding] = []

    def add(code: str, action: Action) -> None:
        result.append(Finding(call_hash, code, action.value))

    if effect_kind is EffectKind.NONE and committed:
        add("READ_ONLY_CALL_HAS_REMOTE_COMMIT", Action.ESCALATE)
    if len(committed) > 1:
        add("DUPLICATE_REMOTE_EFFECT", Action.ESCALATE)

    if runtime_state is RuntimeState.SUCCEEDED:
        if effect_kind is not EffectKind.NONE and len(active_commits) != 1:
            add("SUCCESS_WITHOUT_ONE_ACTIVE_EFFECT", Action.ESCALATE)
        if effect_kind is EffectKind.NONE and compensated:
            add("READ_ONLY_CALL_HAS_COMPENSATION", Action.ESCALATE)
    elif runtime_state is RuntimeState.FAILED:
        _find_failed_effect(
            effect_kind,
            active_commits,
            had_commit=bool(committed),
            has_rejection=rejected_count > 0,
            add=add,
        )
    elif runtime_state is RuntimeState.EXECUTING:
        if rejected_count and not active_commits:
            add("REJECTED_EFFECT_NOT_ACKNOWLEDGED", Action.MARK_FAILED)
        elif lease_expires_at >= observed_at:
            add("CALL_STILL_IN_FLIGHT", Action.WAIT)
        else:
            _find_stranded_effect(effect_kind, active_commits, rejected_count > 0, add)
    else:
        _find_stranded_effect(effect_kind, active_commits, rejected_count > 0, add)

    return result, len(receipts)


def _find_failed_effect(
    effect_kind: EffectKind,
    active_commits: set[str],
    had_commit: bool,
    has_rejection: bool,
    add: Any,
) -> None:
    if active_commits:
        if effect_kind is EffectKind.IDEMPOTENT:
            add("COMMITTED_EFFECT_NOT_ACKNOWLEDGED", Action.MARK_SUCCEEDED)
        elif effect_kind is EffectKind.COMPENSATABLE:
            add("UNCOMPENSATED_PARTIAL_EFFECT", Action.COMPENSATE)
        elif effect_kind is EffectKind.IRREVERSIBLE:
            add("IRREVERSIBLE_EFFECT_AFTER_FAILURE", Action.ESCALATE)
        return
    if effect_kind is EffectKind.NONE or has_rejection or had_commit:
        return
    if effect_kind is EffectKind.IDEMPOTENT:
        add("FAILED_WRITE_WITHOUT_RECEIPT", Action.RETRY_SAME_KEY)
    else:
        add("FAILED_WRITE_WITHOUT_RECEIPT", Action.QUERY_THEN_ESCALATE)


def _find_stranded_effect(
    effect_kind: EffectKind,
    active_commits: set[str],
    has_rejection: bool,
    add: Any,
) -> None:
    if active_commits:
        if effect_kind is EffectKind.IDEMPOTENT:
            add("STRANDED_COMMITTED_EFFECT", Action.MARK_SUCCEEDED)
        elif effect_kind is EffectKind.COMPENSATABLE:
            add("STRANDED_PARTIAL_EFFECT", Action.COMPENSATE)
        else:
            add("STRANDED_IRREVERSIBLE_EFFECT", Action.ESCALATE)
        return
    if has_rejection:
        add("REJECTED_EFFECT_NOT_ACKNOWLEDGED", Action.MARK_FAILED)
        return
    if effect_kind is EffectKind.NONE:
        add("STRANDED_READ", Action.RETRY_READ)
    elif effect_kind is EffectKind.IDEMPOTENT:
        add("STRANDED_IDEMPOTENT_WRITE", Action.RETRY_SAME_KEY)
    else:
        add("STRANDED_EFFECT_WITHOUT_RECEIPT", Action.QUERY_THEN_ESCALATE)


def _parse_receipt(
    receipt: Any,
    *,
    call_intent: str,
    call_idempotency_key: str | None,
    started_at: datetime,
    observed_at: datetime,
    seen_receipts: set[str],
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ArtifactMalformed("RECEIPT_NOT_OBJECT")
    _expect_keys(
        receipt,
        {
            "receipt_id",
            "operation_sha256",
            "intent_sha256",
            "idempotency_key_sha256",
            "status",
            "observed_at",
            "compensates_operation_sha256",
        },
        "RECEIPT_FIELDS",
    )
    receipt_id = _identifier(receipt["receipt_id"], "RECEIPT_ID")
    if receipt_id in seen_receipts:
        raise ArtifactMalformed("DUPLICATE_RECEIPT_ID")
    seen_receipts.add(receipt_id)
    operation = _digest(receipt["operation_sha256"], "OPERATION_SHA256")
    intent = _digest(receipt["intent_sha256"], "RECEIPT_INTENT_SHA256")
    key = _optional_digest(receipt["idempotency_key_sha256"], "RECEIPT_IDEMPOTENCY_KEY")
    status = _enum(ReceiptStatus, receipt["status"], "RECEIPT_STATUS")
    receipt_time = _timestamp(receipt["observed_at"], "RECEIPT_OBSERVED_AT")
    target = _optional_digest(receipt["compensates_operation_sha256"], "COMPENSATES_OPERATION_SHA256")
    if intent != call_intent or key != call_idempotency_key:
        raise ArtifactMalformed("RECEIPT_BINDING_MISMATCH")
    if not started_at <= receipt_time <= observed_at:
        raise ArtifactMalformed("RECEIPT_TIME_ORDER")
    if status is ReceiptStatus.COMPENSATED and target is None:
        raise ArtifactMalformed("COMPENSATION_TARGET_REQUIRED")
    if status is not ReceiptStatus.COMPENSATED and target is not None:
        raise ArtifactMalformed("UNEXPECTED_COMPENSATION_TARGET")
    return {
        "operation_sha256": operation,
        "status": status,
        "observed_at": receipt_time,
        "compensates_operation_sha256": target,
    }


def _expect_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise ArtifactMalformed(code)


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ArtifactMalformed(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ArtifactMalformed(code)
    return value


def _optional_digest(value: Any, code: str) -> str | None:
    return None if value is None else _digest(value, code)


def _timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ArtifactMalformed(code)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ArtifactMalformed(code) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ArtifactMalformed(code)
    return parsed.astimezone(UTC)


def _optional_timestamp(value: Any, code: str) -> datetime | None:
    return None if value is None else _timestamp(value, code)


def _enum(enum_type: type[Enum], value: Any, code: str) -> Any:
    if not isinstance(value, str):
        raise ArtifactMalformed(code)
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ArtifactMalformed(code) from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit agent side-effect reconciliation evidence")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--as-of", help="UTC RFC3339 timestamp; defaults to current UTC time")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    policy = ReconciliationPolicy()
    try:
        raw = args.artifact.read_bytes()
        artifact = load_artifact(raw, policy)
        as_of = _timestamp(args.as_of, "AS_OF") if args.as_of else datetime.now(UTC)
        report = audit_artifact(artifact, as_of=as_of, policy=policy)
        payload = report.to_dict()
        exit_code = 0 if report.accepted else 2
    except (ArtifactMalformed, OSError) as exc:
        code = exc.code if isinstance(exc, ArtifactMalformed) else "ARTIFACT_IO_ERROR"
        payload = {"accepted": False, "error": code, "status": "malformed"}
        exit_code = 3
    if args.output:
        try:
            _write_json(args.output, payload)
        except OSError:
            return 3
    else:
        json.dump(payload, sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
