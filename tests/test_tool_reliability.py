from __future__ import annotations

import json

import pytest

from src.tool_reliability import RetryPolicy, ToolReliabilityGuard


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_retries_transient_failure_with_bounded_backoff():
    calls = {"count": 0}
    delays: list[float] = []

    def operation() -> dict:
        calls["count"] += 1
        if calls["count"] < 3:
            raise TimeoutError("upstream slow")
        return {"ok": True}

    guard = ToolReliabilityGuard(
        RetryPolicy(max_attempts=3, base_delay_seconds=0.5, max_delay_seconds=0.75),
        sleep=delays.append,
    )
    report = guard.execute("search", operation)

    assert report.status == "succeeded"
    assert report.attempts == 3
    assert report.retry_delays_seconds == (0.5, 0.75)
    assert delays == [0.5, 0.75]
    assert json.loads(json.dumps(report.to_dict()))["circuit_state"] == "closed"


def test_non_retryable_failure_stops_after_one_attempt():
    report = ToolReliabilityGuard().execute(
        "write", lambda: (_ for _ in ()).throw(ValueError("invalid payload"))
    )

    assert report.status == "failed"
    assert report.attempts == 1
    assert report.retry_delays_seconds == ()


def test_opens_circuit_after_consecutive_failed_calls():
    clock = Clock()
    guard = ToolReliabilityGuard(
        RetryPolicy(max_attempts=1, circuit_failure_threshold=2, recovery_timeout_seconds=10),
        clock=clock,
        sleep=lambda _delay: None,
    )
    fail = lambda: (_ for _ in ()).throw(ConnectionError("offline"))

    assert guard.execute("lookup", fail).circuit_state == "closed"
    assert guard.execute("lookup", fail).circuit_state == "open"
    blocked = guard.execute("lookup", lambda: {"should_not": "run"})

    assert blocked.status == "circuit_open"
    assert blocked.attempts == 0


def test_half_open_probe_closes_circuit_after_recovery_timeout():
    clock = Clock()
    guard = ToolReliabilityGuard(
        RetryPolicy(max_attempts=1, circuit_failure_threshold=1, recovery_timeout_seconds=5),
        clock=clock,
        sleep=lambda _delay: None,
    )
    guard.execute("lookup", lambda: (_ for _ in ()).throw(OSError("down")))
    clock.advance(5)

    recovered = guard.execute("lookup", lambda: {"ok": True})

    assert recovered.status == "succeeded"
    assert recovered.circuit_state == "closed"


def test_circuits_are_isolated_per_tool_and_can_be_reset():
    guard = ToolReliabilityGuard(
        RetryPolicy(max_attempts=1, circuit_failure_threshold=1),
        sleep=lambda _delay: None,
    )
    guard.execute("broken", lambda: (_ for _ in ()).throw(OSError("down")))

    assert guard.execute("healthy", lambda: {"ok": True}).status == "succeeded"
    guard.reset("broken")
    assert guard.execute("broken", lambda: {"ok": True}).status == "succeeded"


def test_rejects_non_dictionary_tool_output():
    report = ToolReliabilityGuard().execute("bad", lambda: "not-a-dict")

    assert report.status == "failed"
    assert report.errors == ("TypeError: tool operation must return a dictionary",)


def test_rejects_empty_tool_and_non_finite_clock():
    with pytest.raises(ValueError, match="tool must not be empty"):
        ToolReliabilityGuard().execute("", dict)
    with pytest.raises(ValueError, match="clock"):
        ToolReliabilityGuard(clock=lambda: float("nan")).execute("read", dict)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_attempts": 0},
        {"circuit_failure_threshold": 0},
        {"base_delay_seconds": -1},
        {"max_delay_seconds": 0.1, "base_delay_seconds": 0.2},
        {"recovery_timeout_seconds": float("inf")},
    ],
)
def test_rejects_invalid_retry_policy(kwargs):
    with pytest.raises(ValueError):
        RetryPolicy(**kwargs)
