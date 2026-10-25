from __future__ import annotations

from dataclasses import replace

import pytest

from src.reconciliation import (
    ReceiptAuthenticator,
    ReconciliationReceipt,
    RetryAuthorizationReceipt,
)
from src.reconciliation_adapter import (
    AuthoritativeReconciliationCoordinator,
    DownstreamObservation,
    DownstreamOutcome,
    ReconciliationQuery,
    ReconciliationUnavailableError,
)
from src.sqlite_ledger import ClaimDisposition, SQLiteExecutionLedger


KEY = "write:request-7"
REQUEST_SHA256 = "a" * 64
QUERY = ReconciliationQuery(KEY, REQUEST_SHA256, 1)


class Provider:
    provider_id = "payments-primary"

    def __init__(self, observation: DownstreamObservation) -> None:
        self.observation = observation
        self.calls: list[tuple[ReconciliationQuery, float]] = []

    def lookup(
        self,
        query: ReconciliationQuery,
        *,
        timeout_seconds: float,
    ) -> DownstreamObservation:
        self.calls.append((query, timeout_seconds))
        return self.observation


class FailingProvider:
    provider_id = "payments-primary"

    def lookup(
        self,
        query: ReconciliationQuery,
        *,
        timeout_seconds: float,
    ) -> DownstreamObservation:
        raise RuntimeError("secret upstream diagnostic")


def observation(
    outcome: DownstreamOutcome,
    *,
    output: dict[str, object] | None = None,
) -> DownstreamObservation:
    return DownstreamObservation(
        provider_id="payments-primary",
        outcome=outcome,
        key=KEY,
        request_sha256=REQUEST_SHA256,
        fencing_token=1,
        observed_at_ms=100_000,
        output=output,
    )


def authenticator(now: list[float]) -> ReceiptAuthenticator:
    return ReceiptAuthenticator(
        {"current": b"a" * 32},
        signing_key_id="current",
        max_age_seconds=30,
        clock=lambda: now[0],
    )


def coordinator(
    provider: Provider | FailingProvider,
    now: list[float],
    *,
    monotonic=lambda: 1.0,
) -> AuthoritativeReconciliationCoordinator:
    return AuthoritativeReconciliationCoordinator(
        provider,
        authenticator(now),
        lookup_timeout_seconds=0.25,
        max_observation_age_seconds=10,
        max_future_skew_seconds=1,
        clock=lambda: now[0],
        monotonic=monotonic,
    )


def test_committed_observation_issues_verified_success_receipt() -> None:
    now = [100.0]
    provider = Provider(observation(DownstreamOutcome.COMMITTED, output={"payment_id": "p-7"}))
    reconciler = coordinator(provider, now)

    decision = reconciler.reconcile(QUERY, retry_lease_seconds=30)

    assert decision.outcome is DownstreamOutcome.COMMITTED
    assert decision.provider_id == "payments-primary"
    assert len(decision.observation_sha256) == 64
    assert isinstance(decision.receipt, ReconciliationReceipt)
    assert reconciler.authenticator.verify(decision.receipt) == {"payment_id": "p-7"}
    assert provider.calls == [(QUERY, 0.25)]


def test_not_committed_observation_issues_bounded_retry_authorization() -> None:
    now = [100.0]
    reconciler = coordinator(Provider(observation(DownstreamOutcome.NOT_COMMITTED)), now)

    decision = reconciler.reconcile(QUERY, retry_lease_seconds=2.5)

    assert decision.outcome is DownstreamOutcome.NOT_COMMITTED
    assert isinstance(decision.receipt, RetryAuthorizationReceipt)
    assert reconciler.authenticator.verify_retry_authorization(decision.receipt) == 2_500


def test_pending_observation_produces_no_execution_authority() -> None:
    now = [100.0]
    reconciler = coordinator(Provider(observation(DownstreamOutcome.PENDING)), now)

    decision = reconciler.reconcile(QUERY, retry_lease_seconds=30)

    assert decision.outcome is DownstreamOutcome.PENDING
    assert decision.receipt is None


@pytest.mark.parametrize(
    "changed, message",
    [
        (replace(observation(DownstreamOutcome.PENDING), key="other"), "claim identity"),
        (
            replace(observation(DownstreamOutcome.PENDING), request_sha256="b" * 64),
            "claim identity",
        ),
        (
            replace(observation(DownstreamOutcome.PENDING), fencing_token=2),
            "claim identity",
        ),
        (
            replace(observation(DownstreamOutcome.PENDING), provider_id="replica"),
            "provider identity",
        ),
    ],
)
def test_mismatched_provider_identity_never_issues_authority(
    changed: DownstreamObservation,
    message: str,
) -> None:
    with pytest.raises(ReconciliationUnavailableError, match=message):
        coordinator(Provider(changed), [100.0]).reconcile(QUERY, retry_lease_seconds=30)


@pytest.mark.parametrize(
    "changed, message",
    [
        (
            replace(
                observation(DownstreamOutcome.COMMITTED, output={"ok": True}),
                observed_at_ms=89_999,
            ),
            "stale",
        ),
        (
            replace(
                observation(DownstreamOutcome.COMMITTED, output={"ok": True}),
                observed_at_ms=101_001,
            ),
            "future",
        ),
    ],
)
def test_stale_or_future_observation_never_issues_authority(
    changed: DownstreamObservation,
    message: str,
) -> None:
    with pytest.raises(ReconciliationUnavailableError, match=message):
        coordinator(Provider(changed), [100.0]).reconcile(QUERY, retry_lease_seconds=30)


@pytest.mark.parametrize(
    "changed, message",
    [
        (observation(DownstreamOutcome.COMMITTED), "requires output"),
        (
            observation(DownstreamOutcome.NOT_COMMITTED, output={"unexpected": True}),
            "must not include output",
        ),
        (
            observation(DownstreamOutcome.PENDING, output={"unexpected": True}),
            "must not include output",
        ),
    ],
)
def test_contradictory_observation_never_issues_authority(
    changed: DownstreamObservation,
    message: str,
) -> None:
    with pytest.raises(ReconciliationUnavailableError, match=message):
        coordinator(Provider(changed), [100.0]).reconcile(QUERY, retry_lease_seconds=30)


def test_provider_failure_is_normalized_without_leaking_diagnostics() -> None:
    with pytest.raises(ReconciliationUnavailableError, match="provider lookup failed") as caught:
        coordinator(FailingProvider(), [100.0]).reconcile(QUERY, retry_lease_seconds=30)

    assert "secret upstream diagnostic" not in str(caught.value)


def test_response_after_deadline_never_issues_authority() -> None:
    monotonic_values = iter([1.0, 1.251])
    reconciler = coordinator(
        Provider(observation(DownstreamOutcome.NOT_COMMITTED)),
        [100.0],
        monotonic=lambda: next(monotonic_values),
    )

    with pytest.raises(ReconciliationUnavailableError, match="deadline exceeded"):
        reconciler.reconcile(QUERY, retry_lease_seconds=30)


def test_success_decision_resolves_unknown_ledger_without_redispatch(tmp_path) -> None:
    now = [100.0]
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db", clock=lambda: now[0])
    claim = ledger.claim_for_request(KEY, REQUEST_SHA256, lease_seconds=30)
    assert claim.disposition is ClaimDisposition.ACQUIRED
    ledger.mark_claim_unknown(KEY, REQUEST_SHA256, 1)
    reconciler = coordinator(
        Provider(observation(DownstreamOutcome.COMMITTED, output={"saved": 7})),
        now,
    )

    decision = reconciler.reconcile(QUERY, retry_lease_seconds=30)
    assert isinstance(decision.receipt, ReconciliationReceipt)
    ledger.record_authenticated_reconciled_success(decision.receipt, reconciler.authenticator)

    replay = ledger.claim_for_request(KEY, REQUEST_SHA256, lease_seconds=30)
    assert replay.disposition is ClaimDisposition.REPLAYED
    assert replay.output == {"saved": 7}


def test_no_commit_decision_advances_unknown_ledger_fence_once(tmp_path) -> None:
    now = [100.0]
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db", clock=lambda: now[0])
    claim = ledger.claim_for_request(KEY, REQUEST_SHA256, lease_seconds=30)
    assert claim.disposition is ClaimDisposition.ACQUIRED
    ledger.mark_claim_unknown(KEY, REQUEST_SHA256, 1)
    reconciler = coordinator(Provider(observation(DownstreamOutcome.NOT_COMMITTED)), now)

    decision = reconciler.reconcile(QUERY, retry_lease_seconds=5)
    assert isinstance(decision.receipt, RetryAuthorizationReceipt)
    retried = ledger.retry_unknown_claim_authenticated(decision.receipt, reconciler.authenticator)

    assert retried.disposition is ClaimDisposition.ACQUIRED
    assert retried.fencing_token == 2
    assert retried.retry_count == 1
