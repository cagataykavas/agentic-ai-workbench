from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from src.reconciliation import (
    Payload,
    ReceiptAuthenticator,
    ReconciliationReceipt,
    RetryAuthorizationReceipt,
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_PROVIDER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_MAX_OUTPUT_BYTES = 65_536
_MAX_SQLITE_INTEGER = 9_223_372_036_854_775_807
_MAX_REPLICA_ACKNOWLEDGEMENTS = 32


class ReconciliationUnavailableError(RuntimeError):
    """The provider could not produce a safe authoritative decision."""

    code = "authoritative_reconciliation_unavailable"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"{self.code}: {reason}")


class DownstreamOutcome(StrEnum):
    COMMITTED = "committed"
    NOT_COMMITTED = "not_committed"
    PENDING = "pending"


@dataclass(frozen=True, slots=True)
class ReconciliationQuery:
    key: str
    request_sha256: str
    fencing_token: int


@dataclass(frozen=True, slots=True)
class NegativeDurabilityProof:
    """Storage position observed while proving that a claim is absent."""

    authority_epoch: int
    durable_sequence: int
    replica_acknowledgements: int


@dataclass(frozen=True, slots=True)
class NegativeObservationPolicy:
    """Minimum evidence required before absence can authorize a retry."""

    minimum_authority_epoch: int = 1
    minimum_durable_sequence: int | None = None
    required_replica_acknowledgements: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.minimum_authority_epoch) is not int
            or not 0 < self.minimum_authority_epoch <= _MAX_SQLITE_INTEGER
        ):
            raise ValueError("minimum_authority_epoch must be a positive SQLite integer")
        if self.minimum_durable_sequence is not None and (
            type(self.minimum_durable_sequence) is not int
            or not 0 < self.minimum_durable_sequence <= _MAX_SQLITE_INTEGER
        ):
            raise ValueError("minimum_durable_sequence must be a positive SQLite integer")
        if self.required_replica_acknowledgements is not None and (
            type(self.required_replica_acknowledgements) is not int
            or not 0
            < self.required_replica_acknowledgements
            <= _MAX_REPLICA_ACKNOWLEDGEMENTS
        ):
            raise ValueError("required_replica_acknowledgements must be in [1, 32]")
        if (
            self.minimum_durable_sequence is None
            and self.required_replica_acknowledgements is None
        ):
            raise ValueError("negative observation policy requires a sequence or replica threshold")

    def accepts(self, proof: NegativeDurabilityProof) -> bool:
        if proof.authority_epoch < self.minimum_authority_epoch:
            return False
        sequence_satisfied = (
            self.minimum_durable_sequence is not None
            and proof.durable_sequence >= self.minimum_durable_sequence
        )
        replica_satisfied = (
            self.required_replica_acknowledgements is not None
            and proof.replica_acknowledgements >= self.required_replica_acknowledgements
        )
        return sequence_satisfied or replica_satisfied


@dataclass(frozen=True, slots=True)
class DownstreamObservation:
    provider_id: str
    outcome: DownstreamOutcome
    key: str
    request_sha256: str
    fencing_token: int
    observed_at_ms: int
    output: Payload | None = None
    negative_proof: NegativeDurabilityProof | None = None


class AuthoritativeStatusProvider(Protocol):
    provider_id: str

    def lookup(
        self,
        query: ReconciliationQuery,
        *,
        timeout_seconds: float,
    ) -> DownstreamObservation: ...


@dataclass(frozen=True, slots=True)
class AuthorityEpochRequirement:
    """Dynamically loaded controller floor for negative retry evidence."""

    provider_id: str
    minimum_authority_epoch: int
    checkpoint_sha256: str


class AuthorityEpochSource(Protocol):
    def current_requirement(self) -> AuthorityEpochRequirement: ...


@dataclass(frozen=True, slots=True)
class ReconciliationDecision:
    outcome: DownstreamOutcome
    provider_id: str
    observation_sha256: str
    receipt: ReconciliationReceipt | RetryAuthorizationReceipt | None


class AuthoritativeReconciliationCoordinator:
    """Translate one exact downstream observation into bounded signed authority."""

    def __init__(
        self,
        provider: AuthoritativeStatusProvider,
        authenticator: ReceiptAuthenticator,
        *,
        negative_observation_policy: NegativeObservationPolicy,
        authority_epoch_source: AuthorityEpochSource | None = None,
        lookup_timeout_seconds: float = 2.0,
        max_observation_age_seconds: float = 30.0,
        max_future_skew_seconds: float = 2.0,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        provider_id = getattr(provider, "provider_id", None)
        if not isinstance(provider_id, str) or not _PROVIDER_ID_PATTERN.fullmatch(provider_id):
            raise ValueError("provider_id must be 1-64 safe characters")
        self._validate_duration("lookup_timeout_seconds", lookup_timeout_seconds, minimum=0.001, maximum=30)
        self._validate_duration(
            "max_observation_age_seconds",
            max_observation_age_seconds,
            minimum=0,
            maximum=3_600,
        )
        self._validate_duration(
            "max_future_skew_seconds",
            max_future_skew_seconds,
            minimum=0,
            maximum=300,
        )
        if not isinstance(negative_observation_policy, NegativeObservationPolicy):
            raise TypeError("negative_observation_policy must be a NegativeObservationPolicy")
        self.provider = provider
        self.authenticator = authenticator
        self.negative_observation_policy = negative_observation_policy
        self.authority_epoch_source = authority_epoch_source
        self.provider_id = provider_id
        self.lookup_timeout_seconds = float(lookup_timeout_seconds)
        self.max_observation_age_ms = math.floor(max_observation_age_seconds * 1_000)
        self.max_future_skew_ms = math.floor(max_future_skew_seconds * 1_000)
        self._clock = clock
        self._monotonic = monotonic

    @staticmethod
    def _validate_duration(
        name: str,
        value: float,
        *,
        minimum: float,
        maximum: float,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not minimum <= value <= maximum
        ):
            raise ValueError(f"{name} must be finite and in [{minimum:g}, {maximum:g}]")

    @staticmethod
    def _validate_query(query: ReconciliationQuery) -> None:
        if not isinstance(query, ReconciliationQuery):
            raise TypeError("query must be a ReconciliationQuery")
        if not isinstance(query.key, str) or not query.key or len(query.key.encode("utf-8")) > 512:
            raise ValueError("query key must be 1-512 UTF-8 bytes")
        if not isinstance(query.request_sha256, str) or not _SHA256_PATTERN.fullmatch(query.request_sha256):
            raise ValueError("query request_sha256 must be lowercase SHA-256")
        if type(query.fencing_token) is not int or not 0 < query.fencing_token <= _MAX_SQLITE_INTEGER:
            raise ValueError("query fencing_token must be a positive SQLite integer")

    @staticmethod
    def _canonical_negative_proof(
        proof: NegativeDurabilityProof | None,
    ) -> dict[str, int] | None:
        if proof is None:
            return None
        if not isinstance(proof, NegativeDurabilityProof):
            raise ReconciliationUnavailableError("negative durability proof is malformed")
        if (
            type(proof.authority_epoch) is not int
            or not 0 < proof.authority_epoch <= _MAX_SQLITE_INTEGER
            or type(proof.durable_sequence) is not int
            or not 0 <= proof.durable_sequence <= _MAX_SQLITE_INTEGER
            or type(proof.replica_acknowledgements) is not int
            or not 0
            <= proof.replica_acknowledgements
            <= _MAX_REPLICA_ACKNOWLEDGEMENTS
        ):
            raise ReconciliationUnavailableError("negative durability proof is malformed")
        return {
            "authority_epoch": proof.authority_epoch,
            "durable_sequence": proof.durable_sequence,
            "replica_acknowledgements": proof.replica_acknowledgements,
        }

    @staticmethod
    def _canonical_output(output: Payload | None) -> Payload | None:
        if output is None:
            return None
        if not isinstance(output, dict):
            raise ReconciliationUnavailableError("provider output is not a JSON object")
        try:
            encoded = json.dumps(
                output,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ReconciliationUnavailableError("provider output is not finite JSON") from exc
        if len(encoded.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            raise ReconciliationUnavailableError("provider output exceeds 65536 UTF-8 bytes")
        return json.loads(encoded)

    def _validate_observation(
        self,
        query: ReconciliationQuery,
        observation: DownstreamObservation,
    ) -> tuple[DownstreamOutcome, Payload | None, str]:
        if not isinstance(observation, DownstreamObservation):
            raise ReconciliationUnavailableError("provider returned an unsupported response")
        if observation.provider_id != self.provider_id:
            raise ReconciliationUnavailableError("provider identity mismatch")
        if (
            observation.key != query.key
            or observation.request_sha256 != query.request_sha256
            or observation.fencing_token != query.fencing_token
        ):
            raise ReconciliationUnavailableError("provider claim identity mismatch")
        if not isinstance(observation.outcome, DownstreamOutcome):
            raise ReconciliationUnavailableError("provider outcome is unsupported")
        if type(observation.observed_at_ms) is not int or observation.observed_at_ms < 0:
            raise ReconciliationUnavailableError("provider observation time is malformed")
        now_ms = math.floor(self._clock() * 1_000)
        if observation.observed_at_ms > now_ms + self.max_future_skew_ms:
            raise ReconciliationUnavailableError("provider observation is from the future")
        if now_ms - observation.observed_at_ms > self.max_observation_age_ms:
            raise ReconciliationUnavailableError("provider observation is stale")
        output = self._canonical_output(observation.output)
        if observation.outcome is DownstreamOutcome.COMMITTED and output is None:
            raise ReconciliationUnavailableError("committed observation requires output")
        if observation.outcome is not DownstreamOutcome.COMMITTED and output is not None:
            raise ReconciliationUnavailableError("non-committed observation must not include output")
        negative_proof = self._canonical_negative_proof(observation.negative_proof)
        checkpoint_sha256: str | None = None
        if observation.outcome is DownstreamOutcome.NOT_COMMITTED:
            if negative_proof is None:
                raise ReconciliationUnavailableError(
                    "not-committed observation requires a negative durability proof"
                )
            assert observation.negative_proof is not None
            if not self.negative_observation_policy.accepts(observation.negative_proof):
                raise ReconciliationUnavailableError(
                    "negative durability proof does not satisfy retry policy"
                )
            if self.authority_epoch_source is not None:
                try:
                    requirement = self.authority_epoch_source.current_requirement()
                except Exception as exc:
                    raise ReconciliationUnavailableError(
                        "authority epoch checkpoint unavailable"
                    ) from exc
                if not isinstance(requirement, AuthorityEpochRequirement):
                    raise ReconciliationUnavailableError(
                        "authority epoch checkpoint is malformed"
                    )
                if requirement.provider_id != self.provider_id:
                    raise ReconciliationUnavailableError(
                        "authority epoch checkpoint provider mismatch"
                    )
                if (
                    type(requirement.minimum_authority_epoch) is not int
                    or not 0
                    < requirement.minimum_authority_epoch
                    <= _MAX_SQLITE_INTEGER
                    or not isinstance(requirement.checkpoint_sha256, str)
                    or _SHA256_PATTERN.fullmatch(requirement.checkpoint_sha256) is None
                ):
                    raise ReconciliationUnavailableError(
                        "authority epoch checkpoint is malformed"
                    )
                if (
                    observation.negative_proof.authority_epoch
                    < requirement.minimum_authority_epoch
                ):
                    raise ReconciliationUnavailableError(
                        "negative proof is below the controller epoch checkpoint"
                    )
                checkpoint_sha256 = requirement.checkpoint_sha256
        elif negative_proof is not None:
            raise ReconciliationUnavailableError(
                "only not-committed observations may include a negative durability proof"
            )
        document = {
            "fencing_token": query.fencing_token,
            "key_sha256": hashlib.sha256(query.key.encode("utf-8")).hexdigest(),
            "observed_at_ms": observation.observed_at_ms,
            "negative_proof": negative_proof,
            "outcome": observation.outcome.value,
            "output": output,
            "provider_id": observation.provider_id,
            "request_sha256": query.request_sha256,
            "schema_version": 2,
            "authority_epoch_checkpoint_sha256": checkpoint_sha256,
        }
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return observation.outcome, output, hashlib.sha256(encoded).hexdigest()

    def reconcile(
        self,
        query: ReconciliationQuery,
        *,
        retry_lease_seconds: float,
    ) -> ReconciliationDecision:
        """Issue one success/retry receipt, or no authority while still pending."""

        self._validate_query(query)
        started_at = self._monotonic()
        try:
            observation = self.provider.lookup(
                query,
                timeout_seconds=self.lookup_timeout_seconds,
            )
        except Exception as exc:
            raise ReconciliationUnavailableError("provider lookup failed") from exc
        elapsed = self._monotonic() - started_at
        if not math.isfinite(elapsed) or elapsed < 0 or elapsed > self.lookup_timeout_seconds:
            raise ReconciliationUnavailableError("provider lookup deadline exceeded")
        outcome, output, observation_sha256 = self._validate_observation(query, observation)
        receipt: ReconciliationReceipt | RetryAuthorizationReceipt | None
        if outcome is DownstreamOutcome.COMMITTED:
            assert output is not None
            receipt = self.authenticator.issue(
                query.key,
                query.request_sha256,
                query.fencing_token,
                output,
            )
        elif outcome is DownstreamOutcome.NOT_COMMITTED:
            receipt = self.authenticator.issue_retry_authorization(
                query.key,
                query.request_sha256,
                query.fencing_token,
                lease_seconds=retry_lease_seconds,
            )
        else:
            receipt = None
        return ReconciliationDecision(
            outcome=outcome,
            provider_id=self.provider_id,
            observation_sha256=observation_sha256,
            receipt=receipt,
        )
