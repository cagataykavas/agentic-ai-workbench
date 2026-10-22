from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.dag_execution import DagActionStatus, DependencyAction, DependencyExecutor
from src.governed_runtime import IdempotencyPayloadMismatchError, ToolRegistry, ToolSpec
from src.sqlite_ledger import SQLiteExecutionLedger


def run(coroutine):
    return asyncio.run(coroutine)


def registry_with(handler) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ToolSpec("write", "write", handler))
    return registry


def test_exact_request_replays_after_ledger_is_reopened(tmp_path) -> None:
    database = tmp_path / "ledger.db"
    calls = 0

    def handler(arguments: dict) -> dict:
        nonlocal calls
        calls += 1
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
