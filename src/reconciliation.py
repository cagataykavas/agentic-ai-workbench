from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

Payload = dict[str, Any]

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_MAX_OUTPUT_BYTES = 65_536
_MAX_KEYRING_SIZE = 16
_MAX_RECEIPT_AGE_SECONDS = 86_400.0
_MAX_RETRY_LEASE_SECONDS = 3_600.0


class ReceiptAuthenticationError(ValueError):
    """A reconciliation receipt is malformed, stale, or not authentic."""


def _canonical_output(output: Payload) -> str:
    if not isinstance(output, dict):
        raise ReceiptAuthenticationError("receipt output must be a JSON object")
    try:
        encoded = json.dumps(
            output,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ReceiptAuthenticationError("receipt output must be finite JSON") from exc
    if len(encoded.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ReceiptAuthenticationError("receipt output exceeds 65536 UTF-8 bytes")
    return encoded


@dataclass(frozen=True, slots=True)
class ReconciliationReceipt:
    key: str
    request_sha256: str
    fencing_token: int
    output_json: str
    issued_at_ms: int
    key_id: str
    signature: str
    schema_version: int = 1

    def output(self) -> Payload:
        try:
            decoded = json.loads(self.output_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ReceiptAuthenticationError("receipt output is not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise ReceiptAuthenticationError("receipt output must be a JSON object")
        return decoded

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "key": self.key,
            "request_sha256": self.request_sha256,
            "fencing_token": self.fencing_token,
            "output": self.output(),
            "issued_at_ms": self.issued_at_ms,
            "key_id": self.key_id,
            "signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class RetryAuthorizationReceipt:
    """Authentic proof that an exact unknown claim may advance to a new fence."""

    key: str
    request_sha256: str
    fencing_token: int
    retry_lease_ms: int
    issued_at_ms: int
    key_id: str
    signature: str
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_type": "retry_authorization",
            "key": self.key,
            "request_sha256": self.request_sha256,
            "fencing_token": self.fencing_token,
            "retry_lease_ms": self.retry_lease_ms,
            "issued_at_ms": self.issued_at_ms,
            "key_id": self.key_id,
            "signature": self.signature,
        }


class ReceiptAuthenticator:
    """Issue and verify short-lived HMAC receipts for unknown tool outcomes."""

    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        signing_key_id: str,
        max_age_seconds: float = 300.0,
        max_future_skew_seconds: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not 1 <= len(keys) <= _MAX_KEYRING_SIZE:
            raise ValueError("receipt keyring must contain 1-16 keys")
        normalized: dict[str, bytes] = {}
        for key_id, secret in keys.items():
            if not isinstance(key_id, str) or not _KEY_ID_PATTERN.fullmatch(key_id):
                raise ValueError("receipt key IDs must be 1-64 safe characters")
            if not isinstance(secret, bytes) or len(secret) < 32:
                raise ValueError("receipt HMAC keys must contain at least 32 bytes")
            normalized[key_id] = secret
        if signing_key_id not in normalized:
            raise ValueError("signing_key_id must exist in the receipt keyring")
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, (int, float))
            or not math.isfinite(max_age_seconds)
            or not 0 < max_age_seconds <= _MAX_RECEIPT_AGE_SECONDS
        ):
            raise ValueError("max_age_seconds must be finite and in (0, 86400]")
        if (
            isinstance(max_future_skew_seconds, bool)
            or not isinstance(max_future_skew_seconds, (int, float))
            or not math.isfinite(max_future_skew_seconds)
            or not 0 <= max_future_skew_seconds <= 300
        ):
            raise ValueError("max_future_skew_seconds must be finite and in [0, 300]")
        self._keys = normalized
        self.signing_key_id = signing_key_id
        self.max_age_ms = math.floor(max_age_seconds * 1_000)
        self.max_future_skew_ms = math.floor(max_future_skew_seconds * 1_000)
        self._clock = clock

    @staticmethod
    def _validate_identity(key: str, request_sha256: str, fencing_token: int) -> None:
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 512:
            raise ReceiptAuthenticationError("receipt key must be 1-512 UTF-8 bytes")
        if not isinstance(request_sha256, str) or not _SHA256_PATTERN.fullmatch(request_sha256):
            raise ReceiptAuthenticationError("receipt request_sha256 must be lowercase SHA-256")
        if type(fencing_token) is not int or not 0 < fencing_token <= 9_223_372_036_854_775_807:
            raise ReceiptAuthenticationError("receipt fencing_token must be a positive integer")

    @staticmethod
    def _payload(receipt: ReconciliationReceipt) -> bytes:
        canonical = {
            "schema_version": receipt.schema_version,
            "key": receipt.key,
            "request_sha256": receipt.request_sha256,
            "fencing_token": receipt.fencing_token,
            "output": receipt.output(),
            "issued_at_ms": receipt.issued_at_ms,
            "key_id": receipt.key_id,
        }
        return json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _retry_payload(receipt: RetryAuthorizationReceipt) -> bytes:
        canonical = {
            "schema_version": receipt.schema_version,
            "receipt_type": "retry_authorization",
            "key": receipt.key,
            "request_sha256": receipt.request_sha256,
            "fencing_token": receipt.fencing_token,
            "retry_lease_ms": receipt.retry_lease_ms,
            "issued_at_ms": receipt.issued_at_ms,
            "key_id": receipt.key_id,
        }
        return json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    def _verification_secret(
        self,
        *,
        key_id: str,
        issued_at_ms: int,
        signature: str,
    ) -> bytes:
        if not isinstance(key_id, str) or not _KEY_ID_PATTERN.fullmatch(key_id):
            raise ReceiptAuthenticationError("receipt key_id is malformed")
        secret = self._keys.get(key_id)
        if secret is None:
            raise ReceiptAuthenticationError("receipt key_id is unknown")
        if type(issued_at_ms) is not int or issued_at_ms < 0:
            raise ReceiptAuthenticationError("receipt issued_at_ms is malformed")
        if not isinstance(signature, str) or not _SHA256_PATTERN.fullmatch(signature):
            raise ReceiptAuthenticationError("receipt signature is malformed")
        now_ms = math.floor(self._clock() * 1_000)
        if issued_at_ms > now_ms + self.max_future_skew_ms:
            raise ReceiptAuthenticationError("receipt was issued too far in the future")
        if now_ms - issued_at_ms > self.max_age_ms:
            raise ReceiptAuthenticationError("receipt is stale")
        return secret

    def issue(
        self,
        key: str,
        request_sha256: str,
        fencing_token: int,
        output: Payload,
    ) -> ReconciliationReceipt:
        self._validate_identity(key, request_sha256, fencing_token)
        output_json = _canonical_output(output)
        issued_at_ms = math.floor(self._clock() * 1_000)
        unsigned = ReconciliationReceipt(
            key=key,
            request_sha256=request_sha256,
            fencing_token=fencing_token,
            output_json=output_json,
            issued_at_ms=issued_at_ms,
            key_id=self.signing_key_id,
            signature="",
        )
        signature = hmac.new(
            self._keys[self.signing_key_id],
            self._payload(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return ReconciliationReceipt(
            key=unsigned.key,
            request_sha256=unsigned.request_sha256,
            fencing_token=unsigned.fencing_token,
            output_json=unsigned.output_json,
            issued_at_ms=unsigned.issued_at_ms,
            key_id=unsigned.key_id,
            signature=signature,
        )

    def verify(self, receipt: ReconciliationReceipt) -> Payload:
        if not isinstance(receipt, ReconciliationReceipt):
            raise ReceiptAuthenticationError("receipt has an unsupported type")
        if receipt.schema_version != 1:
            raise ReceiptAuthenticationError("receipt schema_version is unsupported")
        self._validate_identity(receipt.key, receipt.request_sha256, receipt.fencing_token)
        secret = self._verification_secret(
            key_id=receipt.key_id,
            issued_at_ms=receipt.issued_at_ms,
            signature=receipt.signature,
        )
        output = receipt.output()
        if _canonical_output(output) != receipt.output_json:
            raise ReceiptAuthenticationError("receipt output is not canonical JSON")
        expected = hmac.new(secret, self._payload(receipt), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, receipt.signature):
            raise ReceiptAuthenticationError("receipt signature is invalid")
        return output

    @staticmethod
    def _retry_lease_ms(lease_seconds: float) -> int:
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(lease_seconds)
            or not 0 < lease_seconds <= _MAX_RETRY_LEASE_SECONDS
        ):
            raise ValueError("retry lease_seconds must be finite and in (0, 3600]")
        return max(1, math.floor(lease_seconds * 1_000))

    def issue_retry_authorization(
        self,
        key: str,
        request_sha256: str,
        fencing_token: int,
        *,
        lease_seconds: float,
    ) -> RetryAuthorizationReceipt:
        """Authorize one fenced retry after proving no side effect committed."""
        self._validate_identity(key, request_sha256, fencing_token)
        unsigned = RetryAuthorizationReceipt(
            key=key,
            request_sha256=request_sha256,
            fencing_token=fencing_token,
            retry_lease_ms=self._retry_lease_ms(lease_seconds),
            issued_at_ms=math.floor(self._clock() * 1_000),
            key_id=self.signing_key_id,
            signature="",
        )
        signature = hmac.new(
            self._keys[self.signing_key_id],
            self._retry_payload(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return RetryAuthorizationReceipt(
            key=unsigned.key,
            request_sha256=unsigned.request_sha256,
            fencing_token=unsigned.fencing_token,
            retry_lease_ms=unsigned.retry_lease_ms,
            issued_at_ms=unsigned.issued_at_ms,
            key_id=unsigned.key_id,
            signature=signature,
        )

    def verify_retry_authorization(
        self,
        receipt: RetryAuthorizationReceipt,
    ) -> int:
        """Return the signed retry lease in milliseconds after full verification."""
        if not isinstance(receipt, RetryAuthorizationReceipt):
            raise ReceiptAuthenticationError("retry authorization has an unsupported type")
        if receipt.schema_version != 1:
            raise ReceiptAuthenticationError("receipt schema_version is unsupported")
        self._validate_identity(receipt.key, receipt.request_sha256, receipt.fencing_token)
        if type(receipt.retry_lease_ms) is not int or not 1 <= receipt.retry_lease_ms <= int(
            _MAX_RETRY_LEASE_SECONDS * 1_000
        ):
            raise ReceiptAuthenticationError("retry authorization lease is malformed")
        secret = self._verification_secret(
            key_id=receipt.key_id,
            issued_at_ms=receipt.issued_at_ms,
            signature=receipt.signature,
        )
        expected = hmac.new(secret, self._retry_payload(receipt), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, receipt.signature):
            raise ReceiptAuthenticationError("receipt signature is invalid")
        return receipt.retry_lease_ms
