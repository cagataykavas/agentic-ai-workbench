# Tool retry budgets and circuit breaking

Agent tool loops can amplify a downstream incident when every planning step
retries an unhealthy dependency. `src.tool_reliability` provides a dependency-
free guard with bounded exponential backoff and an independent circuit per tool.

```python
guard = ToolReliabilityGuard(
    RetryPolicy(
        max_attempts=3,
        base_delay_seconds=0.1,
        max_delay_seconds=1.0,
        circuit_failure_threshold=3,
        recovery_timeout_seconds=30.0,
    )
)
report = guard.execute("lookup_order", lambda: lookup_order(order_id))
```

Only explicitly retryable transport failures are retried by default. Retry delay
is capped, exhausted calls count once toward the circuit, and a successful call
resets the failure count. Once open, the circuit rejects calls without executing
the tool. After the recovery timeout it permits a half-open probe. Reports retain
attempt count, errors, delays, output, and final circuit state as JSON evidence.

## Safety boundary and limits

Retries are not safe for arbitrary side effects. Use this guard only around
idempotent operations or provide a downstream idempotency key. The in-memory
circuit state is process-local and does not coordinate replicas. The reference
implementation is synchronous and does not enforce per-attempt deadlines;
production async tools should combine it with cancellation, shared circuit state
where appropriate, metrics, jitter, and a total request deadline.
