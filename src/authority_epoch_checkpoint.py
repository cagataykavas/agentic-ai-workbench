from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from src.reconciliation_adapter import AuthorityEpochRequirement

_CHECKPOINT_FIELDS = frozenset(
    {
        "schema_version",
        "provider_id",
        "generation",
        "minimum_authority_epoch",
        "issued_at_ms",
        "key_id",
        "signature",
    }
)
_PROVIDER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAX_INTEGER = 9_223_372_036_854_775_807
_DOMAIN = b"agentic-ai-authority-epoch-checkpoint-v1\0"


class AuthorityEpochCheckpointError(RuntimeError):
    """The controller checkpoint could not establish a safe epoch floor."""


@dataclass(frozen=True, slots=True)
class AuthorityEpochCheckpoint:
    schema_version: int
    provider_id: str
    generation: int
    minimum_authority_epoch: int
    issued_at_ms: int
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        _safe_identifier(self.provider_id, "provider_id", _PROVIDER_ID_PATTERN)
        _positive_integer(self.generation, "generation")
        _positive_integer(self.minimum_authority_epoch, "minimum_authority_epoch")
        _nonnegative_integer(self.issued_at_ms, "issued_at_ms")
        _safe_identifier(self.key_id, "key_id", _KEY_ID_PATTERN)
        if not isinstance(self.signature, str) or _SHA256_PATTERN.fullmatch(self.signature) is None:
            raise ValueError("signature must be a lowercase HMAC-SHA256 digest")

    def unsigned_document(self) -> dict[str, str | int]:
        return {
            "generation": self.generation,
            "issued_at_ms": self.issued_at_ms,
            "key_id": self.key_id,
            "minimum_authority_epoch": self.minimum_authority_epoch,
            "provider_id": self.provider_id,
            "schema_version": self.schema_version,
        }

    def document(self) -> dict[str, str | int]:
        return {**self.unsigned_document(), "signature": self.signature}

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(self.document())).hexdigest()


CheckpointLoader = Callable[[], tuple[str, str]]


class SignedAuthorityEpochSource:
    """Verify an atomically loaded checkpoint against an external head digest.

    The loader must return the checkpoint JSON and the rollback-protected digest
    from one strongly consistent read. The document is reloaded for every negative
    reconciliation decision so a stale process-local epoch cannot authorize retry.
    """

    def __init__(
        self,
        *,
        provider_id: str,
        checkpoint_loader: CheckpointLoader,
        keyring: Mapping[str, bytes],
        max_age_seconds: float = 300,
        max_future_skew_seconds: float = 5,
        clock: Callable[[], float] = time.time,
    ) -> None:
        _safe_identifier(provider_id, "provider_id", _PROVIDER_ID_PATTERN)
        if not callable(checkpoint_loader):
            raise TypeError("checkpoint_loader must be callable")
        if not isinstance(keyring, Mapping) or not keyring:
            raise ValueError("keyring must contain at least one verification key")
        copied: dict[str, bytes] = {}
        for key_id, secret in keyring.items():
            _safe_identifier(key_id, "key_id", _KEY_ID_PATTERN)
            if not isinstance(secret, bytes) or len(secret) < 32:
                raise ValueError("checkpoint keys must contain at least 32 bytes")
            copied[key_id] = secret
        self._validate_duration("max_age_seconds", max_age_seconds, 1, 86_400)
        self._validate_duration("max_future_skew_seconds", max_future_skew_seconds, 0, 300)
        if not callable(clock):
            raise TypeError("clock must be callable")
        self.provider_id = provider_id
        self._checkpoint_loader = checkpoint_loader
        self._keyring = MappingProxyType(copied)
        self._max_age_ms = math.floor(max_age_seconds * 1_000)
        self._max_future_skew_ms = math.floor(max_future_skew_seconds * 1_000)
        self._clock = clock
        self._lock = threading.Lock()
        self._highest_generation = 0
        self._highest_minimum_epoch = 0
        self._generation_digest: str | None = None

    @staticmethod
    def _validate_duration(name: str, value: float, minimum: float, maximum: float) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not minimum <= value <= maximum
        ):
            raise ValueError(f"{name} must be finite and in [{minimum:g}, {maximum:g}]")

    def current_requirement(self) -> AuthorityEpochRequirement:
        try:
            text, anchored_digest = self._checkpoint_loader()
        except Exception as exc:
            raise AuthorityEpochCheckpointError("checkpoint_load_failed") from exc
        if not isinstance(text, str) or len(text.encode("utf-8")) > 16_384:
            raise AuthorityEpochCheckpointError("checkpoint_document_invalid")
        if not isinstance(anchored_digest, str) or _SHA256_PATTERN.fullmatch(anchored_digest) is None:
            raise AuthorityEpochCheckpointError("checkpoint_anchor_invalid")
        checkpoint = load_authority_epoch_checkpoint(text)
        if not hmac.compare_digest(checkpoint.digest, anchored_digest):
            raise AuthorityEpochCheckpointError("checkpoint_anchor_mismatch")
        if checkpoint.provider_id != self.provider_id:
            raise AuthorityEpochCheckpointError("checkpoint_provider_mismatch")
        secret = self._keyring.get(checkpoint.key_id)
        if secret is None:
            raise AuthorityEpochCheckpointError("checkpoint_key_unknown")
        expected = hmac.new(
            secret,
            _DOMAIN + _canonical(checkpoint.unsigned_document()),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, checkpoint.signature):
            raise AuthorityEpochCheckpointError("checkpoint_signature_invalid")
        now_ms = math.floor(self._clock() * 1_000)
        if checkpoint.issued_at_ms > now_ms + self._max_future_skew_ms:
            raise AuthorityEpochCheckpointError("checkpoint_from_future")
        if now_ms - checkpoint.issued_at_ms > self._max_age_ms:
            raise AuthorityEpochCheckpointError("checkpoint_stale")
        with self._lock:
            if checkpoint.generation < self._highest_generation:
                raise AuthorityEpochCheckpointError("checkpoint_generation_regressed")
            if checkpoint.minimum_authority_epoch < self._highest_minimum_epoch:
                raise AuthorityEpochCheckpointError("checkpoint_epoch_regressed")
            if (
                checkpoint.generation == self._highest_generation
                and self._generation_digest is not None
                and not hmac.compare_digest(checkpoint.digest, self._generation_digest)
            ):
                raise AuthorityEpochCheckpointError("checkpoint_generation_equivocated")
            self._highest_generation = checkpoint.generation
            self._highest_minimum_epoch = checkpoint.minimum_authority_epoch
            self._generation_digest = checkpoint.digest
        return AuthorityEpochRequirement(
            provider_id=checkpoint.provider_id,
            minimum_authority_epoch=checkpoint.minimum_authority_epoch,
            checkpoint_sha256=checkpoint.digest,
        )


def sign_authority_epoch_checkpoint(
    *,
    provider_id: str,
    generation: int,
    minimum_authority_epoch: int,
    issued_at_ms: int,
    key_id: str,
    secret: bytes,
) -> AuthorityEpochCheckpoint:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("checkpoint signing key must contain at least 32 bytes")
    unsigned = {
        "generation": generation,
        "issued_at_ms": issued_at_ms,
        "key_id": key_id,
        "minimum_authority_epoch": minimum_authority_epoch,
        "provider_id": provider_id,
        "schema_version": 1,
    }
    placeholder = AuthorityEpochCheckpoint(**unsigned, signature="0" * 64)
    signature = hmac.new(
        secret,
        _DOMAIN + _canonical(placeholder.unsigned_document()),
        hashlib.sha256,
    ).hexdigest()
    return AuthorityEpochCheckpoint(**unsigned, signature=signature)


def load_authority_epoch_checkpoint(text: str) -> AuthorityEpochCheckpoint:
    if not isinstance(text, str):
        raise TypeError("checkpoint JSON must be text")
    try:
        document = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise AuthorityEpochCheckpointError("checkpoint_json_invalid") from exc
    if not isinstance(document, dict) or set(document) != _CHECKPOINT_FIELDS:
        raise AuthorityEpochCheckpointError("checkpoint_schema_invalid")
    try:
        return AuthorityEpochCheckpoint(**document)
    except (TypeError, ValueError) as exc:
        raise AuthorityEpochCheckpointError("checkpoint_fields_invalid") from exc


def dump_authority_epoch_checkpoint(checkpoint: AuthorityEpochCheckpoint) -> str:
    if not isinstance(checkpoint, AuthorityEpochCheckpoint):
        raise TypeError("checkpoint must be an AuthorityEpochCheckpoint")
    return _canonical(checkpoint.document()).decode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise AuthorityEpochCheckpointError("checkpoint_duplicate_field")
        document[key] = value
    return document


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _safe_identifier(value: Any, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe identifier")
    return value


def _nonnegative_integer(value: Any, name: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INTEGER:
        raise ValueError(f"{name} must be a non-negative bounded integer")
    return value


def _positive_integer(value: Any, name: str) -> int:
    parsed = _nonnegative_integer(value, name)
    if parsed == 0:
        raise ValueError(f"{name} must be positive")
    return parsed
