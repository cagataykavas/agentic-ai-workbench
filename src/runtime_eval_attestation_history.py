from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

HISTORY_ENTRY_SCHEMA = "runtime-benchmark-attestation-history-entry/v1"
MAX_HISTORY_BYTES = 1024 * 1024
MAX_HISTORY_ENTRIES = 4096

_DOMAIN = b"agentic-ai-runtime-benchmark-attestation-history-v1\0"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_ENTRY_FIELDS = frozenset(
    {
        "attestation_policy_sha256",
        "entry_sha256",
        "manifest_sha256",
        "previous_entry_sha256",
        "receipt_evidence_sha256",
        "schema_version",
        "sequence",
        "verification_mode",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "attestation_policy_sha256",
        "evidence_sha256",
        "manifest_sha256",
        "provenance_verified",
        "schema_version",
        "status",
        "verification_mode",
    }
)


class RuntimeBenchmarkAttestationHistoryError(RuntimeError):
    """The retained benchmark acceptance history was unsafe or inconsistent."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def append_attestation_acceptance(path: Path, receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Append a verified, privacy-reduced receipt to a locked hash chain.

    This is an integrity and equivocation signal, not an external transparency log:
    a host that can replace the whole file can also replace its history.
    """
    normalized_receipt = _validate_receipt(receipt)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > MAX_HISTORY_BYTES
        ):
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_file_unsafe")
        payload = _read_locked(descriptor, metadata.st_size)
        entries = _load_history(payload)
        receipt_digest = normalized_receipt["evidence_sha256"]
        for entry in entries:
            if entry["receipt_evidence_sha256"] == receipt_digest:
                if not _entry_matches_receipt(entry, normalized_receipt):
                    raise RuntimeBenchmarkAttestationHistoryError(
                        "attestation_history_receipt_equivocation"
                    )
                return entry
        if len(entries) >= MAX_HISTORY_ENTRIES:
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_full")
        unsigned: dict[str, Any] = {
            "attestation_policy_sha256": normalized_receipt["attestation_policy_sha256"],
            "manifest_sha256": normalized_receipt["manifest_sha256"],
            "previous_entry_sha256": entries[-1]["entry_sha256"] if entries else "0" * 64,
            "receipt_evidence_sha256": receipt_digest,
            "schema_version": HISTORY_ENTRY_SCHEMA,
            "sequence": len(entries) + 1,
            "verification_mode": normalized_receipt["verification_mode"],
        }
        entry = {**unsigned, "entry_sha256": _entry_digest(unsigned)}
        encoded = _canonical(entry) + b"\n"
        if metadata.st_size + len(encoded) > MAX_HISTORY_BYTES:
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_full")
        os.lseek(descriptor, 0, os.SEEK_END)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeBenchmarkAttestationHistoryError("attestation_history_write_failed")
            view = view[written:]
        os.fsync(descriptor)
        return entry
    except RuntimeBenchmarkAttestationHistoryError:
        raise
    except OSError as exc:
        raise RuntimeBenchmarkAttestationHistoryError("attestation_history_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_attestation_history(path: Path) -> list[dict[str, Any]]:
    """Load and validate a retained history without following a final symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > MAX_HISTORY_BYTES
        ):
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_file_unsafe")
        return _load_history(_read_locked(descriptor, metadata.st_size))
    except RuntimeBenchmarkAttestationHistoryError:
        raise
    except OSError as exc:
        raise RuntimeBenchmarkAttestationHistoryError("attestation_history_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_locked(descriptor: int, expected_size: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    size = 0
    while chunk := os.read(descriptor, 8192):
        size += len(chunk)
        if size > MAX_HISTORY_BYTES:
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_too_large")
        chunks.append(chunk)
    if size != expected_size:
        raise RuntimeBenchmarkAttestationHistoryError("attestation_history_changed_during_read")
    return b"".join(chunks)


def _load_history(payload: bytes) -> list[dict[str, Any]]:
    if not payload:
        return []
    if not payload.endswith(b"\n"):
        raise RuntimeBenchmarkAttestationHistoryError("attestation_history_truncated")
    lines = payload.splitlines()
    if len(lines) > MAX_HISTORY_ENTRIES:
        raise RuntimeBenchmarkAttestationHistoryError("attestation_history_full")
    entries: list[dict[str, Any]] = []
    previous = "0" * 64
    for sequence, line in enumerate(lines, start=1):
        try:
            document = json.loads(line, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_json_invalid") from exc
        if not isinstance(document, dict) or set(document) != _ENTRY_FIELDS:
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_schema_invalid")
        if _canonical(document) != line:
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_noncanonical")
        unsigned = {key: value for key, value in document.items() if key != "entry_sha256"}
        if (
            document["schema_version"] != HISTORY_ENTRY_SCHEMA
            or type(document["sequence"]) is not int
            or document["sequence"] != sequence
            or document["previous_entry_sha256"] != previous
            or document["verification_mode"] not in {"online", "offline"}
            or any(
                not isinstance(document[field], str) or _DIGEST.fullmatch(document[field]) is None
                for field in (
                    "attestation_policy_sha256",
                    "entry_sha256",
                    "manifest_sha256",
                    "previous_entry_sha256",
                    "receipt_evidence_sha256",
                )
            )
            or document["entry_sha256"] != _entry_digest(unsigned)
        ):
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_chain_invalid")
        entries.append(document)
        previous = document["entry_sha256"]
    return entries


def _validate_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping) or set(receipt) != _RECEIPT_FIELDS:
        raise RuntimeBenchmarkAttestationHistoryError("attestation_receipt_schema_invalid")
    normalized = dict(receipt)
    evidence = normalized.pop("evidence_sha256", None)
    if (
        normalized.get("schema_version") != "runtime-benchmark-attestation-verification/v1"
        or normalized.get("status") != "pass"
        or normalized.get("provenance_verified") is not True
        or normalized.get("verification_mode") not in {"online", "offline"}
        or any(
            not isinstance(normalized.get(field), str)
            or _DIGEST.fullmatch(normalized[field]) is None
            for field in ("attestation_policy_sha256", "manifest_sha256")
        )
        or not isinstance(evidence, str)
        or _DIGEST.fullmatch(evidence) is None
        or hashlib.sha256(_canonical(normalized)).hexdigest() != evidence
    ):
        raise RuntimeBenchmarkAttestationHistoryError("attestation_receipt_invalid")
    return {**normalized, "evidence_sha256": evidence}


def _entry_matches_receipt(entry: Mapping[str, Any], receipt: Mapping[str, Any]) -> bool:
    return all(
        entry[field] == receipt[field]
        for field in ("attestation_policy_sha256", "manifest_sha256", "verification_mode")
    )


def _entry_digest(unsigned: Mapping[str, Any]) -> str:
    return hashlib.sha256(_DOMAIN + _canonical(unsigned)).hexdigest()


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise RuntimeBenchmarkAttestationHistoryError("attestation_history_duplicate_field")
        document[key] = value
    return document
