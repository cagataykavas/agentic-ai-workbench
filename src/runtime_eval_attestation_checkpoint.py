from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from src.runtime_eval_attestation_history import load_attestation_history

CHECKPOINT_SCHEMA = "runtime-benchmark-attestation-history-checkpoint/v1"
VERIFICATION_SCHEMA = "runtime-benchmark-attestation-history-checkpoint-verification/v1"
SIGNATURE_ALGORITHM = "Ed25519"
MAX_CHECKPOINT_BYTES = 32 * 1024

_DIGEST = re.compile(r"[0-9a-f]{64}")
_SOURCE_REVISION = re.compile(r"[0-9a-f]{40}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_TOP_LEVEL_FIELDS = frozenset({"checkpoint", "public_key", "signature"})
_CHECKPOINT_FIELDS = frozenset(
    {
        "attestation_policy_sha256",
        "checkpoint_key_id",
        "entry_count",
        "head_entry_sha256",
        "issued_at",
        "manifest_sha256",
        "schema_version",
        "source_revision_sha256",
    }
)
_PUBLIC_KEY_FIELDS = frozenset({"encoding", "sha256", "value"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "encoding", "value"})

Signer = Callable[[bytes], bytes]
SignatureVerifier = Callable[[bytes, bytes, bytes], bool]


class RuntimeBenchmarkCheckpointError(RuntimeError):
    """The retained history checkpoint is malformed, untrusted, or inconsistent."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def create_attestation_history_checkpoint(
    history_path: Path,
    *,
    source_revision: str,
    checkpoint_key_id: str,
    issued_at: str,
    public_key_der: bytes,
    signer: Signer,
) -> dict[str, Any]:
    """Sign one validated history head through an injected HSM/KMS-compatible signer."""
    if not isinstance(public_key_der, bytes) or not 32 <= len(public_key_der) <= 4096:
        raise RuntimeBenchmarkCheckpointError("checkpoint_public_key_invalid")
    checkpoint = _checkpoint_claims(
        history_path,
        source_revision=source_revision,
        checkpoint_key_id=checkpoint_key_id,
        issued_at=issued_at,
    )
    signature = signer(_canonical(checkpoint))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise RuntimeBenchmarkCheckpointError("checkpoint_signature_invalid")
    return {
        "checkpoint": checkpoint,
        "public_key": {
            "encoding": "base64-der-subject-public-key-info",
            "sha256": hashlib.sha256(public_key_der).hexdigest(),
            "value": base64.b64encode(public_key_der).decode("ascii"),
        },
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "encoding": "base64",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_attestation_history_checkpoint(
    history_path: Path,
    envelope: object,
    *,
    expected_source_revision: str,
    expected_checkpoint_key_id: str,
    expected_public_key_sha256: str,
    signature_verifier: SignatureVerifier,
) -> dict[str, Any]:
    """Verify an independently retained checkpoint against the current history head."""
    if not isinstance(envelope, dict) or set(envelope) != _TOP_LEVEL_FIELDS:
        raise RuntimeBenchmarkCheckpointError("checkpoint_envelope_schema_invalid")
    checkpoint = envelope.get("checkpoint")
    public_key = envelope.get("public_key")
    signature_document = envelope.get("signature")
    if not isinstance(checkpoint, dict) or set(checkpoint) != _CHECKPOINT_FIELDS:
        raise RuntimeBenchmarkCheckpointError("checkpoint_claims_schema_invalid")
    if not isinstance(public_key, dict) or set(public_key) != _PUBLIC_KEY_FIELDS:
        raise RuntimeBenchmarkCheckpointError("checkpoint_public_key_schema_invalid")
    if (
        not isinstance(signature_document, dict)
        or set(signature_document) != _SIGNATURE_FIELDS
        or signature_document.get("algorithm") != SIGNATURE_ALGORITHM
        or signature_document.get("encoding") != "base64"
        or public_key.get("encoding") != "base64-der-subject-public-key-info"
    ):
        raise RuntimeBenchmarkCheckpointError("checkpoint_signature_schema_invalid")
    key = _canonical_base64(public_key.get("value"), "checkpoint_public_key_invalid")
    signature = _canonical_base64(signature_document.get("value"), "checkpoint_signature_invalid")
    if len(signature) != 64:
        raise RuntimeBenchmarkCheckpointError("checkpoint_signature_invalid")
    key_digest = hashlib.sha256(key).hexdigest()
    if (
        not isinstance(expected_public_key_sha256, str)
        or _DIGEST.fullmatch(expected_public_key_sha256) is None
        or public_key.get("sha256") != key_digest
        or key_digest != expected_public_key_sha256
    ):
        raise RuntimeBenchmarkCheckpointError("checkpoint_public_key_mismatch")
    try:
        valid = signature_verifier(key, signature, _canonical(checkpoint))
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise RuntimeBenchmarkCheckpointError("checkpoint_verification_unavailable") from exc
    if valid is not True:
        raise RuntimeBenchmarkCheckpointError("checkpoint_signature_invalid")
    expected = _checkpoint_claims(
        history_path,
        source_revision=expected_source_revision,
        checkpoint_key_id=expected_checkpoint_key_id,
        issued_at=checkpoint.get("issued_at"),
    )
    if checkpoint != expected:
        raise RuntimeBenchmarkCheckpointError("checkpoint_history_mismatch")
    receipt: dict[str, Any] = {
        "attestation_policy_sha256": checkpoint["attestation_policy_sha256"],
        "checkpoint_key_id_sha256": hashlib.sha256(expected_checkpoint_key_id.encode("ascii")).hexdigest(),
        "checkpoint_key_sha256": key_digest,
        "checkpoint_sha256": hashlib.sha256(_canonical(envelope)).hexdigest(),
        "entry_count": checkpoint["entry_count"],
        "head_entry_sha256": checkpoint["head_entry_sha256"],
        "issued_at": checkpoint["issued_at"],
        "manifest_sha256": checkpoint["manifest_sha256"],
        "schema_version": VERIFICATION_SCHEMA,
        "source_revision_sha256": checkpoint["source_revision_sha256"],
        "status": "pass",
    }
    receipt["evidence_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return receipt


def verify_ed25519_signature(
    public_key_der: bytes,
    signature: bytes,
    message: bytes,
    *,
    executable: str = "openssl",
    timeout_seconds: int = 10,
) -> bool:
    """Verify an Ed25519 signature through a bounded OpenSSL subprocess."""
    if not 1 <= timeout_seconds <= 60:
        raise ValueError("OpenSSL timeout must be in [1, 60] seconds")
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_key_path = root / "public-key.der"
            signature_path = root / "signature.bin"
            message_path = root / "message.bin"
            for path, payload in (
                (public_key_path, public_key_der),
                (signature_path, signature),
                (message_path, message),
            ):
                path.write_bytes(payload)
                path.chmod(0o600)
            completed = subprocess.run(
                [
                    executable,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-keyform",
                    "DER",
                    "-inkey",
                    str(public_key_path),
                    "-rawin",
                    "-in",
                    str(message_path),
                    "-sigfile",
                    str(signature_path),
                ],
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("OpenSSL Ed25519 verification is unavailable") from exc
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RuntimeError("OpenSSL rejected the Ed25519 verification request")


def load_attestation_history_checkpoint(path: Path) -> object:
    """Read one bounded checkpoint without following or racing a final symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_CHECKPOINT_BYTES:
            raise RuntimeBenchmarkCheckpointError("checkpoint_file_invalid")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 8192):
            size += len(chunk)
            if size > MAX_CHECKPOINT_BYTES:
                raise RuntimeBenchmarkCheckpointError("checkpoint_file_invalid")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            size != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise RuntimeBenchmarkCheckpointError("checkpoint_file_changed")
    except OSError as exc:
        raise RuntimeBenchmarkCheckpointError("checkpoint_file_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        return json.loads(b"".join(chunks), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeBenchmarkCheckpointError("checkpoint_json_invalid") from exc


def _checkpoint_claims(
    history_path: Path,
    *,
    source_revision: object,
    checkpoint_key_id: object,
    issued_at: object,
) -> dict[str, Any]:
    if not isinstance(source_revision, str) or _SOURCE_REVISION.fullmatch(source_revision) is None:
        raise RuntimeBenchmarkCheckpointError("checkpoint_source_revision_invalid")
    if not isinstance(checkpoint_key_id, str) or _KEY_ID.fullmatch(checkpoint_key_id) is None:
        raise RuntimeBenchmarkCheckpointError("checkpoint_key_id_invalid")
    if not isinstance(issued_at, str):
        raise RuntimeBenchmarkCheckpointError("checkpoint_issued_at_invalid")
    try:
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RuntimeBenchmarkCheckpointError("checkpoint_issued_at_invalid") from exc
    entries = load_attestation_history(history_path)
    if not entries:
        raise RuntimeBenchmarkCheckpointError("checkpoint_history_empty")
    head = entries[-1]
    return {
        "attestation_policy_sha256": head["attestation_policy_sha256"],
        "checkpoint_key_id": checkpoint_key_id,
        "entry_count": len(entries),
        "head_entry_sha256": head["entry_sha256"],
        "issued_at": issued_at,
        "manifest_sha256": head["manifest_sha256"],
        "schema_version": CHECKPOINT_SCHEMA,
        "source_revision_sha256": hashlib.sha256(source_revision.encode("ascii")).hexdigest(),
    }


def _canonical_base64(value: object, code: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise RuntimeBenchmarkCheckpointError(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeBenchmarkCheckpointError(code) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise RuntimeBenchmarkCheckpointError(code)
    return decoded


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise RuntimeBenchmarkCheckpointError("checkpoint_duplicate_field")
        document[key] = value
    return document
