from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

STATUS_SCHEMA = "runtime-benchmark-checkpoint-key-status/v1"
SIGNATURE_ALGORITHM = "Ed25519"
MAX_STATUS_BYTES = 32 * 1024
MAX_STATUS_LIFETIME = timedelta(hours=24)
MAX_GENERATION = (1 << 31) - 1
GENESIS_STATUS_SHA256 = "0" * 64

_DIGEST = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_TOP_LEVEL_FIELDS = frozenset({"authority_public_key", "signature", "status"})
_STATUS_FIELDS = frozenset(
    {
        "checkpoint_key_id",
        "checkpoint_public_key_sha256",
        "expires_at",
        "generation",
        "issued_at",
        "previous_status_sha256",
        "schema_version",
        "state",
        "status_authority_key_id",
    }
)
_PUBLIC_KEY_FIELDS = frozenset({"encoding", "sha256", "value"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "encoding", "value"})

Signer = Callable[[bytes], bytes]
SignatureVerifier = Callable[[bytes, bytes, bytes], bool]


class RuntimeBenchmarkCheckpointKeyStatusError(RuntimeError):
    """A checkpoint-key status is malformed, stale, revoked, or untrusted."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def create_checkpoint_key_status(
    *,
    checkpoint_key_id: str,
    checkpoint_public_key_sha256: str,
    state: str,
    generation: int,
    previous_status_sha256: str,
    status_authority_key_id: str,
    issued_at: str,
    expires_at: str,
    authority_public_key_der: bytes,
    signer: Signer,
) -> dict[str, Any]:
    """Create one generation-bound status through an independent signer."""
    if not isinstance(authority_public_key_der, bytes) or not 32 <= len(authority_public_key_der) <= 4096:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_authority_key_invalid")
    authority_digest = hashlib.sha256(authority_public_key_der).hexdigest()
    if authority_digest == checkpoint_public_key_sha256:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_key_role_reuse")
    status = _status_claims(
        checkpoint_key_id=checkpoint_key_id,
        checkpoint_public_key_sha256=checkpoint_public_key_sha256,
        state=state,
        generation=generation,
        previous_status_sha256=previous_status_sha256,
        status_authority_key_id=status_authority_key_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    signature = signer(_canonical(status))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_signature_invalid")
    return {
        "authority_public_key": {
            "encoding": "base64-der-subject-public-key-info",
            "sha256": authority_digest,
            "value": base64.b64encode(authority_public_key_der).decode("ascii"),
        },
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "encoding": "base64",
            "value": base64.b64encode(signature).decode("ascii"),
        },
        "status": status,
    }


def verify_checkpoint_key_status(
    envelope: object,
    *,
    expected_checkpoint_key_id: str,
    expected_checkpoint_public_key_sha256: str,
    expected_generation: int,
    expected_previous_status_sha256: str,
    expected_status_authority_key_id: str,
    expected_status_authority_public_key_sha256: str,
    verification_time: str,
    signature_verifier: SignatureVerifier,
) -> dict[str, Any]:
    """Verify authority, generation, predecessor, freshness, and active state."""
    if not isinstance(envelope, dict) or set(envelope) != _TOP_LEVEL_FIELDS:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_envelope_schema_invalid")
    status = envelope.get("status")
    public_key = envelope.get("authority_public_key")
    signature_document = envelope.get("signature")
    if not isinstance(status, dict) or set(status) != _STATUS_FIELDS:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_claims_schema_invalid")
    if not isinstance(public_key, dict) or set(public_key) != _PUBLIC_KEY_FIELDS:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_authority_schema_invalid")
    if (
        not isinstance(signature_document, dict)
        or set(signature_document) != _SIGNATURE_FIELDS
        or signature_document.get("algorithm") != SIGNATURE_ALGORITHM
        or signature_document.get("encoding") != "base64"
        or public_key.get("encoding") != "base64-der-subject-public-key-info"
    ):
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_signature_schema_invalid")
    authority_key = _canonical_base64(public_key.get("value"), "status_authority_key_invalid")
    signature = _canonical_base64(signature_document.get("value"), "status_signature_invalid")
    if len(signature) != 64:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_signature_invalid")
    authority_digest = hashlib.sha256(authority_key).hexdigest()
    if (
        not isinstance(expected_status_authority_public_key_sha256, str)
        or _DIGEST.fullmatch(expected_status_authority_public_key_sha256) is None
        or public_key.get("sha256") != authority_digest
        or authority_digest != expected_status_authority_public_key_sha256
    ):
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_authority_key_mismatch")
    if (
        authority_digest == expected_checkpoint_public_key_sha256
        or expected_status_authority_key_id == expected_checkpoint_key_id
    ):
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_key_role_reuse")
    try:
        valid = signature_verifier(authority_key, signature, _canonical(status))
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_verification_unavailable") from exc
    if valid is not True:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_signature_invalid")

    expected = _status_claims(
        checkpoint_key_id=expected_checkpoint_key_id,
        checkpoint_public_key_sha256=expected_checkpoint_public_key_sha256,
        state=status.get("state"),
        generation=expected_generation,
        previous_status_sha256=expected_previous_status_sha256,
        status_authority_key_id=expected_status_authority_key_id,
        issued_at=status.get("issued_at"),
        expires_at=status.get("expires_at"),
    )
    if status != expected:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_binding_mismatch")
    verified_at = _parse_time(verification_time, "status_verification_time_invalid")
    issued_at = _parse_time(status["issued_at"], "status_issued_at_invalid")
    expires_at = _parse_time(status["expires_at"], "status_expires_at_invalid")
    if verified_at < issued_at:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_not_yet_valid")
    if verified_at >= expires_at:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_expired")
    if status["state"] != "active":
        raise RuntimeBenchmarkCheckpointKeyStatusError("checkpoint_key_revoked")
    return {
        "checkpoint_key_status_authority_sha256": authority_digest,
        "checkpoint_key_status_generation": status["generation"],
        "checkpoint_key_status_previous_sha256": status["previous_status_sha256"],
        "checkpoint_key_status_sha256": hashlib.sha256(_canonical(envelope)).hexdigest(),
        "checkpoint_key_status_valid_until": status["expires_at"],
    }


def load_checkpoint_key_status(path: Path) -> object:
    """Read one bounded status without following or racing a final symlink."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= MAX_STATUS_BYTES:
            raise RuntimeBenchmarkCheckpointKeyStatusError("status_file_invalid")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 8192):
            size += len(chunk)
            if size > MAX_STATUS_BYTES:
                raise RuntimeBenchmarkCheckpointKeyStatusError("status_file_invalid")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            size != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
        ):
            raise RuntimeBenchmarkCheckpointKeyStatusError("status_file_changed")
    except OSError as exc:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_file_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        return json.loads(b"".join(chunks), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_json_invalid") from exc


def _status_claims(
    *,
    checkpoint_key_id: object,
    checkpoint_public_key_sha256: object,
    state: object,
    generation: object,
    previous_status_sha256: object,
    status_authority_key_id: object,
    issued_at: object,
    expires_at: object,
) -> dict[str, Any]:
    if not isinstance(checkpoint_key_id, str) or _KEY_ID.fullmatch(checkpoint_key_id) is None:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_checkpoint_key_id_invalid")
    if (
        not isinstance(checkpoint_public_key_sha256, str)
        or _DIGEST.fullmatch(checkpoint_public_key_sha256) is None
    ):
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_checkpoint_key_invalid")
    if state not in {"active", "revoked"}:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_state_invalid")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= MAX_GENERATION
    ):
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_generation_invalid")
    if (
        not isinstance(previous_status_sha256, str)
        or _DIGEST.fullmatch(previous_status_sha256) is None
        or (generation == 1) != (previous_status_sha256 == GENESIS_STATUS_SHA256)
    ):
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_predecessor_invalid")
    if (
        not isinstance(status_authority_key_id, str)
        or _KEY_ID.fullmatch(status_authority_key_id) is None
        or status_authority_key_id == checkpoint_key_id
    ):
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_authority_key_id_invalid")
    issued = _parse_time(issued_at, "status_issued_at_invalid")
    expires = _parse_time(expires_at, "status_expires_at_invalid")
    if not issued < expires <= issued + MAX_STATUS_LIFETIME:
        raise RuntimeBenchmarkCheckpointKeyStatusError("status_lifetime_invalid")
    return {
        "checkpoint_key_id": checkpoint_key_id,
        "checkpoint_public_key_sha256": checkpoint_public_key_sha256,
        "expires_at": expires_at,
        "generation": generation,
        "issued_at": issued_at,
        "previous_status_sha256": previous_status_sha256,
        "schema_version": STATUS_SCHEMA,
        "state": state,
        "status_authority_key_id": status_authority_key_id,
    }


def _parse_time(value: object, code: str) -> datetime:
    if not isinstance(value, str):
        raise RuntimeBenchmarkCheckpointKeyStatusError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RuntimeBenchmarkCheckpointKeyStatusError(code) from exc


def _canonical_base64(value: object, code: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise RuntimeBenchmarkCheckpointKeyStatusError(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeBenchmarkCheckpointKeyStatusError(code) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise RuntimeBenchmarkCheckpointKeyStatusError(code)
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
            raise RuntimeBenchmarkCheckpointKeyStatusError("status_duplicate_field")
        document[key] = value
    return document
