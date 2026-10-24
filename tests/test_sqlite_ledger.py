from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.dag_execution import (
    DagActionStatus,
    DependencyAction,
    DependencyExecutor,
    get_current_fencing_token,
)
from src.governed_runtime import IdempotencyPayloadMismatchError, ToolRegistry, ToolSpec
from src.sqlite_ledger import (
    ClaimDisposition,
    SQLiteExecutionLedger,
    StaleFencingTokenError,
)


def run(coroutine):
    return asyncio.run(coroutine)


def registry_with(handler) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ToolSpec("write", "write", handler))
    return registry


def request_digest(tool: str, arguments: dict) -> str:
    encoded = json.dumps(
        {"tool": tool, "arguments": arguments},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def test_exact_request_replays_after_ledger_is_reopened(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    calls = 0
    observed_tokens: list[int | None] = []

    def handler(arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        observed_tokens.append(get_current_fencing_token())
        return {"saved": arguments["value"]}

    action = DependencyAction(
        "write-1",
        "write",
        {"value": 7},
        idempotency_key="request-7",
    )
    first = run(
        DependencyExecutor(
            registry_with(handler),
            ledger=SQLiteExecutionLedger(database),
        ).execute("first process", [action])
    )
    replay = run(
        DependencyExecutor(
            registry_with(handler),
            ledger=SQLiteExecutionLedger(database),
        ).execute("replacement process", [action])
    )

    assert first.results[0].status is DagActionStatus.SUCCEEDED
    assert replay.results[0].status is DagActionStatus.REPLAYED
    assert replay.results[0].output == {"saved": 7}
    assert calls == 1
    assert observed_tokens == [1]


def test_payload_mismatch_fails_closed_after_restart(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    calls = 0

    def handler(arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"saved": arguments["value"]}

    first_executor = DependencyExecutor(
        registry_with(handler),
        ledger=SQLiteExecutionLedger(database),
    )
    run(
        first_executor.execute(
            "original",
            [DependencyAction("first", "write", {"value": 1}, idempotency_key="request-1")],
        )
    )
    changed = run(
        DependencyExecutor(
            registry_with(handler),
            ledger=SQLiteExecutionLedger(database),
        ).execute(
            "changed",
            [DependencyAction("second", "write", {"value": 2}, idempotency_key="request-1")],
        )
    )

    assert changed.results[0].status is DagActionStatus.FAILED
    assert changed.results[0].error_code == "idempotency_key_payload_mismatch"
    assert calls == 1


def test_first_terminal_result_wins_under_concurrent_commits(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    ledger = SQLiteExecutionLedger(database)

    def commit(value: int) -> None:
        SQLiteExecutionLedger(database).record_for_request(
            "write:request-1",
            "a" * 64,
            {"winner": value},
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(commit, range(32)))

    winner = ledger.get_for_request("write:request-1", "a" * 64)
    assert winner is not None
    assert winner["winner"] in range(32)
    assert ledger.get_for_request("write:request-1", "a" * 64) == winner


def test_concurrent_changed_payload_cannot_replace_terminal_result(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    ledger = SQLiteExecutionLedger(database)
    ledger.record_for_request("write:request-1", "a" * 64, {"winner": "original"})

    def overwrite(_value: int) -> None:
        with pytest.raises(IdempotencyPayloadMismatchError):
            SQLiteExecutionLedger(database).record_for_request(
                "write:request-1",
                "b" * 64,
                {"winner": "changed"},
            )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(overwrite, range(16)))

    assert ledger.get_for_request("write:request-1", "a" * 64) == {"winner": "original"}


def test_file_backing_and_positive_timeout_are_required(tmp_path) -> None:
    with pytest.raises(ValueError, match="file-backed"):
        SQLiteExecutionLedger(":memory:")
    with pytest.raises(ValueError, match="finite and positive"):
        SQLiteExecutionLedger(tmp_path / "ledger.db", timeout_seconds=0)


@pytest.mark.parametrize("value", [True, -1, 101, 1.5])
def test_retry_budget_policy_is_bounded(value, tmp_path) -> None:
    with pytest.raises(ValueError, match="max_retry_attempts"):
        SQLiteExecutionLedger(tmp_path / "ledger.db", max_retry_attempts=value)


def test_existing_claim_table_migrates_with_conservative_retry_budget(tmp_path) -> None:
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE execution_claims (
                key TEXT PRIMARY KEY,
                request_sha256 TEXT NOT NULL,
                fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
                lease_expires_at_ms INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('running', 'unknown')),
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) STRICT
            """
        )
        connection.execute(
            """
            INSERT INTO execution_claims (
                key, request_sha256, fencing_token, lease_expires_at_ms, state
            ) VALUES ('write:legacy', ?, 1, 0, 'unknown')
            """,
            ("a" * 64,),
        )

    ledger = SQLiteExecutionLedger(database, max_retry_attempts=100)
    migrated = ledger.claim_for_request("write:legacy", "a" * 64, lease_seconds=30)

    assert migrated.disposition is ClaimDisposition.UNKNOWN
    assert migrated.retry_count == 0
    assert migrated.retry_limit == 3


def test_concurrent_workers_obtain_exactly_one_execution_claim(tmp_path) -> None:
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db")

    def claim(_worker: int):
        return ledger.claim_for_request(
            "write:request-1",
            "a" * 64,
            lease_seconds=30,
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        claims = list(pool.map(claim, range(64)))

    assert sum(item.disposition is ClaimDisposition.ACQUIRED for item in claims) == 1
    assert sum(item.disposition is ClaimDisposition.BUSY for item in claims) == 63
    assert {item.fencing_token for item in claims} == {1}


def test_expired_claim_requires_reconciliation_and_increments_fence(tmp_path) -> None:
    now = [100.0]
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db", clock=lambda: now[0])
    first = ledger.claim_for_request("write:request-1", "a" * 64, lease_seconds=0.05)

    now[0] = 100.06
    expired = ledger.claim_for_request("write:request-1", "a" * 64, lease_seconds=0.05)
    retry = ledger.retry_unknown_claim(
        "write:request-1",
        "a" * 64,
        expected_fencing_token=1,
        lease_seconds=0.05,
    )

    assert first.disposition is ClaimDisposition.ACQUIRED
    assert expired.disposition is ClaimDisposition.UNKNOWN
    assert retry.disposition is ClaimDisposition.ACQUIRED
    assert retry.fencing_token == 2
    with pytest.raises(StaleFencingTokenError, match="ownership"):
        ledger.complete_claim("write:request-1", "a" * 64, 1, {"worker": "stale"})

    ledger.complete_claim("write:request-1", "a" * 64, 2, {"worker": "reconciled"})
    replay = ledger.claim_for_request("write:request-1", "a" * 64, lease_seconds=0.05)
    assert replay.disposition is ClaimDisposition.REPLAYED
    assert replay.output == {"worker": "reconciled"}


def test_unfenced_terminal_writer_cannot_bypass_active_claim(tmp_path) -> None:
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db")
    ledger.claim_for_request("write:request-1", "a" * 64, lease_seconds=30)

    with pytest.raises(StaleFencingTokenError, match="fenced completion"):
        ledger.record_for_request("write:request-1", "a" * 64, {"unsafe": True})
    with pytest.raises(StaleFencingTokenError, match="fenced completion"):
        ledger.record("write:request-1", {"unsafe": True})


def test_executor_fences_concurrent_dispatch_and_exposes_token(tmp_path) -> None:
    database = tmp_path / "ledger.db"

    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        observed_tokens: list[int | None] = []

        async def handler(_arguments: dict) -> dict:
            observed_tokens.append(get_current_fencing_token())
            started.set()
            await release.wait()
            return {"saved": True}

        action = DependencyAction(
            "write-1",
            "write",
            {"value": 1},
            idempotency_key="request-1",
        )
        first_task = asyncio.create_task(
            DependencyExecutor(
                registry_with(handler),
                ledger=SQLiteExecutionLedger(database),
            ).execute("first worker", [action])
        )
        await started.wait()
        competing = await DependencyExecutor(
            registry_with(handler),
            ledger=SQLiteExecutionLedger(database),
        ).execute("competing worker", [action])
        release.set()
        first = await first_task

        assert first.results[0].status is DagActionStatus.SUCCEEDED
        assert first.results[0].fencing_token == 1
        assert competing.results[0].status is DagActionStatus.FAILED
        assert competing.results[0].error_code == "idempotency_claim_busy"
        assert observed_tokens == [1]
        assert get_current_fencing_token() is None

    run(scenario())


def test_handler_failure_blocks_automatic_retry_until_receipt_reconciliation(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    calls = 0

    def uncertain_handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        raise TimeoutError("remote outcome is not trustworthy")

    action = DependencyAction(
        "write-1",
        "write",
        {"value": 7},
        idempotency_key="request-7",
    )
    first = run(
        DependencyExecutor(
            registry_with(uncertain_handler),
            ledger=SQLiteExecutionLedger(database),
        ).execute("uncertain write", [action])
    )
    blocked_retry = run(
        DependencyExecutor(
            registry_with(uncertain_handler),
            ledger=SQLiteExecutionLedger(database),
        ).execute("automatic retry", [action])
    )

    assert first.results[0].error_code == "tool_outcome_unknown"
    assert blocked_retry.results[0].error_code == "idempotency_outcome_unknown"
    assert calls == 1

    ledger = SQLiteExecutionLedger(database)
    ledger.record_reconciled_success(
        "write:request-7",
        request_digest("write", {"value": 7}),
        expected_fencing_token=1,
        output={"saved": 7, "receipt": "verified"},
    )
    replay = run(
        DependencyExecutor(
            registry_with(uncertain_handler),
            ledger=ledger,
        ).execute("receipt-backed retry", [action])
    )
    assert replay.results[0].status is DagActionStatus.REPLAYED
    assert replay.results[0].output == {"saved": 7, "receipt": "verified"}
    assert calls == 1


def test_validation_failure_releases_claim_before_handler_dispatch(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    calls = 0

    def handler(_arguments: dict) -> dict:
        nonlocal calls
        calls += 1
        return {"saved": True}

    def reject(_arguments: dict) -> None:
        raise ValueError("invalid")

    rejected_registry = ToolRegistry()
    rejected_registry.register(ToolSpec("write", "write", handler, validator=reject))
    action = DependencyAction("write-1", "write", {}, idempotency_key="request-1")
    rejected = run(
        DependencyExecutor(
            rejected_registry,
            ledger=SQLiteExecutionLedger(database),
        ).execute("rejected", [action])
    )
    accepted = run(
        DependencyExecutor(
            registry_with(handler),
            ledger=SQLiteExecutionLedger(database),
        ).execute("accepted", [action])
    )

    assert rejected.results[0].error_code == "ValueError"
    assert accepted.results[0].status is DagActionStatus.SUCCEEDED
    assert calls == 1


def test_claim_identity_and_lease_policy_fail_closed(tmp_path) -> None:
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db")
    with pytest.raises(ValueError, match="SHA-256"):
        ledger.claim_for_request("write:key", "not-a-digest", lease_seconds=1)
    with pytest.raises(ValueError, match="lease_seconds"):
        ledger.claim_for_request("write:key", "a" * 64, lease_seconds=0)
    with pytest.raises(ValueError, match="lease_seconds"):
        ledger.claim_for_request("write:key", "a" * 64, lease_seconds=True)
    with pytest.raises(ValueError, match="fencing_token"):
        ledger.complete_claim("write:key", "a" * 64, True, {})
    with pytest.raises(ValueError, match="claim_lease_seconds"):
        DependencyExecutor(registry_with(lambda _arguments: {}), claim_lease_seconds=0)
