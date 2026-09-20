from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.1
    max_delay_seconds: float = 2.0
    circuit_failure_threshold: int = 3
    recovery_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.circuit_failure_threshold < 1:
            raise ValueError("attempt and circuit thresholds must be positive")
        values = (
            self.base_delay_seconds,
            self.max_delay_seconds,
            self.recovery_timeout_seconds,
        )
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("delay and timeout values must be finite and non-negative")
        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError("max_delay_seconds must be at least base_delay_seconds")


@dataclass(frozen=True)
class ToolAttemptReport:
    tool: str
    status: str
    attempts: int
    output: dict[str, Any] | None
    errors: tuple[str, ...]
    retry_delays_seconds: tuple[float, ...]
    circuit_state: str

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["errors"] = list(self.errors)
        payload["retry_delays_seconds"] = list(self.retry_delays_seconds)
        return payload


@dataclass
class _CircuitState:
    consecutive_failures: int = 0
    opened_at: float | None = None


class ToolReliabilityGuard:
    """Apply bounded retries and an independent circuit breaker per tool."""

    def __init__(
        self,
        policy: RetryPolicy | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.policy = policy or RetryPolicy()
        self._clock = clock
        self._sleep = sleep
        self._states: dict[str, _CircuitState] = {}

    def _state(self, tool: str) -> _CircuitState:
        if not tool:
            raise ValueError("tool must not be empty")
        return self._states.setdefault(tool, _CircuitState())

    def execute(
        self,
        tool: str,
        operation: Callable[[], dict[str, Any]],
        *,
        retryable: tuple[type[Exception], ...] = (TimeoutError, ConnectionError, OSError),
    ) -> ToolAttemptReport:
        state = self._state(tool)
        now = self._clock()
        if not math.isfinite(now):
            raise ValueError("clock returned a non-finite value")

        if state.opened_at is not None:
            if now - state.opened_at < self.policy.recovery_timeout_seconds:
                return ToolAttemptReport(tool, "circuit_open", 0, None, (), (), "open")
            circuit_state = "half_open"
        else:
            circuit_state = "closed"

        errors: list[str] = []
        delays: list[float] = []
        attempts = 0
        succeeded_output: dict[str, Any] | None = None
        exhausted = False

        for attempt in range(1, self.policy.max_attempts + 1):
            attempts = attempt
            try:
                output = operation()
                if not isinstance(output, dict):
                    raise TypeError("tool operation must return a dictionary")
                succeeded_output = output
                break
            except retryable as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
                if attempt == self.policy.max_attempts:
                    exhausted = True
                    break
                delay = min(
                    self.policy.max_delay_seconds,
                    self.policy.base_delay_seconds * (2 ** (attempt - 1)),
                )
                delays.append(delay)
                self._sleep(delay)
            except (TypeError, ValueError, RuntimeError) as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
                exhausted = True
                break

        if succeeded_output is not None:
            state.consecutive_failures = 0
            state.opened_at = None
            return ToolAttemptReport(
                tool,
                "succeeded",
                attempts,
                succeeded_output,
                tuple(errors),
                tuple(delays),
                "closed",
            )

        if exhausted:
            state.consecutive_failures += 1
            if state.consecutive_failures >= self.policy.circuit_failure_threshold:
                state.opened_at = now
                circuit_state = "open"
        return ToolAttemptReport(
            tool, "failed", attempts, None, tuple(errors), tuple(delays), circuit_state
        )

    def reset(self, tool: str) -> None:
        self._states.pop(tool, None)
