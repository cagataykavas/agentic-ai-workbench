from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from src.sqlite_ledger import (
    ClaimDisposition,
    RetryBudgetExhaustedError,
    SQLiteExecutionLedger,
)


KEY = "write:request-7"
REQUEST_SHA256 = "a" * 64


def acquire(ledger: SQLiteExecutionLedger, *, lease_seconds: float = 30) -> int:
    claim = ledger.claim_for_request(
        KEY,
        REQUEST_SHA256,
        lease_seconds=lease_seconds,
    )
    assert claim.disposition is ClaimDisposition.ACQUIRED
    assert claim.fencing_token is not None
    return claim.fencing_token


def test_empty_snapshot_is_bounded_and_key_free(tmp_path) -> None:
    snapshot = SQLiteExecutionLedger(tmp_path / "ledger.db").snapshot()

    assert snapshot.as_dict() == {
        "schema_version": 1,
        "terminal_results": 0,
        "running_claims": 0,
        "unknown_claims": 0,
        "exhausted_unknown_claims": 0,
        "active_retry_attempts": 0,
        "unknown_transition_total": 0,
        "retry_authorized_total": 0,
        "retry_budget_exhausted_total": 0,
    }
    assert KEY not in str(snapshot.as_dict())
    assert REQUEST_SHA256 not in str(snapshot.as_dict())


def test_snapshot_tracks_retry_lifecycle_without_claim_labels(tmp_path) -> None:
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db", max_retry_attempts=1)
    first_token = acquire(ledger)
    assert ledger.snapshot().running_claims == 1

    ledger.mark_claim_unknown(KEY, REQUEST_SHA256, first_token)
    unknown = ledger.snapshot()
    assert unknown.unknown_claims == 1
    assert unknown.unknown_transition_total == 1

    retry = ledger.retry_unknown_claim(
        KEY,
        REQUEST_SHA256,
        first_token,
        lease_seconds=30,
    )
    assert retry.fencing_token == 2
    after_retry = ledger.snapshot()
    assert after_retry.running_claims == 1
    assert after_retry.active_retry_attempts == 1
    assert after_retry.retry_authorized_total == 1

    ledger.mark_claim_unknown(KEY, REQUEST_SHA256, 2)
    with pytest.raises(RetryBudgetExhaustedError):
        ledger.retry_unknown_claim(KEY, REQUEST_SHA256, 2, lease_seconds=30)

    exhausted = ledger.snapshot()
    assert exhausted.running_claims == 0
    assert exhausted.unknown_claims == 1
    assert exhausted.exhausted_unknown_claims == 1
    assert exhausted.unknown_transition_total == 2
    assert exhausted.retry_budget_exhausted_total == 1

    ledger.record_reconciled_success(
        KEY,
        REQUEST_SHA256,
        expected_fencing_token=2,
        output={"saved": True},
    )
    terminal = ledger.snapshot()
    assert terminal.terminal_results == 1
    assert terminal.running_claims == terminal.unknown_claims == 0
    assert terminal.active_retry_attempts == 0
    assert terminal.retry_authorized_total == 1
    assert terminal.retry_budget_exhausted_total == 1


def test_snapshot_transitions_expired_claim_once(tmp_path) -> None:
    now = [100.0]
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db", clock=lambda: now[0])
    acquire(ledger, lease_seconds=0.05)
    now[0] += 0.06

    first = ledger.snapshot()
    second = ledger.snapshot()

    assert first.running_claims == 0
    assert first.unknown_claims == 1
    assert first.unknown_transition_total == 1
    assert second == first


def test_metrics_survive_reopen_and_legacy_database_migration(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    ledger = SQLiteExecutionLedger(database, max_retry_attempts=0)
    token = acquire(ledger)
    ledger.mark_claim_unknown(KEY, REQUEST_SHA256, token)
    with pytest.raises(RetryBudgetExhaustedError):
        ledger.retry_unknown_claim(KEY, REQUEST_SHA256, token, lease_seconds=30)

    reopened = SQLiteExecutionLedger(database, max_retry_attempts=100).snapshot()

    assert reopened.unknown_transition_total == 1
    assert reopened.retry_budget_exhausted_total == 1
    assert reopened.exhausted_unknown_claims == 1


def test_concurrent_exhaustion_rejections_are_counted_atomically(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    ledger = SQLiteExecutionLedger(database, max_retry_attempts=0)
    token = acquire(ledger)
    ledger.mark_claim_unknown(KEY, REQUEST_SHA256, token)

    def attempt(_delivery: int) -> str:
        try:
            SQLiteExecutionLedger(database).retry_unknown_claim(
                KEY,
                REQUEST_SHA256,
                token,
                lease_seconds=30,
            )
        except RetryBudgetExhaustedError:
            return "exhausted"
        return "unsafe_retry"

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(attempt, range(64)))

    assert outcomes == ["exhausted"] * 64
    snapshot = ledger.snapshot()
    assert snapshot.retry_budget_exhausted_total == 64
    assert snapshot.retry_authorized_total == 0
    assert snapshot.unknown_claims == snapshot.exhausted_unknown_claims == 1
