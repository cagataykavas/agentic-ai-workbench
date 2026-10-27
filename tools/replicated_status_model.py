from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from src.reconciliation_adapter import DownstreamOutcome, ReconciliationQuery

_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}")
_REQUEST_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAX_OUTPUT_BYTES = 65_536


class ReplicationAcknowledgementUnavailable(RuntimeError):
    """The primary committed, but the requested replica count did not confirm it."""

    code = "replication_acknowledgement_unavailable"

    def __init__(self) -> None:
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class ReplicatedCommitEvidence:
    epoch: int
    sequence: int
    replica_acknowledgements: int
    operation_token_sha256: str


@dataclass(frozen=True, slots=True)
class ModelObservation:
    outcome: DownstreamOutcome
    output: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class _Record:
    output_json: str
    operation_token: str
    sequence: int


class ReplicatedStatusModel:
    """Deterministic primary/replica model for reconciliation fault injection.

    Commits are immediately visible on the primary and reach the replica only
    when ``replicate_all`` is called. Promoting the replica discards primary-only
    records, making the asynchronous acknowledgement loss window reproducible.
    """

    def __init__(self) -> None:
        self._primary: dict[tuple[str, str, int], _Record] = {}
        self._replica: dict[tuple[str, str, int], _Record] = {}
        self._epoch = 1
        self._sequence = 0
        self._lock = threading.Lock()

    @staticmethod
    def _identity(query: ReconciliationQuery) -> tuple[str, str, int]:
        if not isinstance(query, ReconciliationQuery):
            raise TypeError("query must be a ReconciliationQuery")
        if not isinstance(query.key, str) or not query.key or len(query.key.encode("utf-8")) > 512:
            raise ValueError("query key must be 1-512 UTF-8 bytes")
        if not isinstance(query.request_sha256, str) or not _REQUEST_SHA256_PATTERN.fullmatch(
            query.request_sha256
        ):
            raise ValueError("query request_sha256 must be lowercase SHA-256")
        if type(query.fencing_token) is not int or not 0 < query.fencing_token <= 9_223_372_036_854_775_807:
            raise ValueError("query fencing_token must be a positive SQLite integer")
        return (query.key, query.request_sha256, query.fencing_token)

    @staticmethod
    def _canonical_output(output: Mapping[str, Any]) -> str:
        if not isinstance(output, Mapping):
            raise TypeError("output must be a mapping")
        try:
            encoded = json.dumps(
                dict(output),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("output must be finite JSON") from exc
        if len(encoded.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            raise ValueError("output exceeds 65536 UTF-8 bytes")
        return encoded

    @staticmethod
    def _validate_operation_token(operation_token: str) -> None:
        if not isinstance(operation_token, str) or not _TOKEN_PATTERN.fullmatch(operation_token):
            raise ValueError("operation_token must be canonical lowercase SHA-256")

    def commit(
        self,
        query: ReconciliationQuery,
        output: Mapping[str, Any],
        *,
        operation_token: str,
        required_replica_acknowledgements: int = 0,
    ) -> ReplicatedCommitEvidence:
        """Commit idempotently, then enforce an acknowledgement threshold."""

        identity = self._identity(query)
        output_json = self._canonical_output(output)
        self._validate_operation_token(operation_token)
        if (
            isinstance(required_replica_acknowledgements, bool)
            or type(required_replica_acknowledgements) is not int
            or required_replica_acknowledgements not in (0, 1)
        ):
            raise ValueError("required_replica_acknowledgements must be 0 or 1")

        with self._lock:
            record = self._primary.get(identity)
            if record is None:
                self._sequence += 1
                record = _Record(output_json, operation_token, self._sequence)
                self._primary[identity] = record
            elif record.operation_token != operation_token or record.output_json != output_json:
                raise ValueError("claim identity already belongs to a different operation")

            replica_acknowledgements = int(self._replica.get(identity) == record)
            if replica_acknowledgements < required_replica_acknowledgements:
                raise ReplicationAcknowledgementUnavailable
            return ReplicatedCommitEvidence(
                epoch=self._epoch,
                sequence=record.sequence,
                replica_acknowledgements=replica_acknowledgements,
                operation_token_sha256=hashlib.sha256(operation_token.encode("ascii")).hexdigest(),
            )

    def replicate_all(self) -> int:
        """Apply all current primary records to the replica."""

        with self._lock:
            changed = sum(self._replica.get(key) != value for key, value in self._primary.items())
            self._replica = dict(self._primary)
            return changed

    def promote_replica(self) -> int:
        """Promote the replica and discard state known only to the old primary."""

        with self._lock:
            self._primary = dict(self._replica)
            self._replica = {}
            self._epoch += 1
            return self._epoch

    def observe(self, query: ReconciliationQuery) -> ModelObservation:
        identity = self._identity(query)
        with self._lock:
            record = self._primary.get(identity)
            if record is None:
                return ModelObservation(DownstreamOutcome.NOT_COMMITTED, None)
            output = json.loads(record.output_json)
            assert isinstance(output, dict)
            return ModelObservation(DownstreamOutcome.COMMITTED, output)
