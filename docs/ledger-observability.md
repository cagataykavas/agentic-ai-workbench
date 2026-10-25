# Execution-ledger observability

The SQLite execution ledger exposes a bounded, key-free operational snapshot:

```python
snapshot = ledger.snapshot()
emit_metrics(snapshot.as_dict())
```

The snapshot contains current gauges for terminal results, running claims, unknown claims, exhausted
unknown claims and retry attempts retained by active claims. It also contains durable counters for
unknown transitions, authorized retries and retry-budget rejections. No idempotency key, request
digest, tool argument or output is emitted, so these fields can be exported as low-cardinality
metrics without turning claim identity into a label.

Unknown transitions and retry counters update in the same `BEGIN IMMEDIATE` transaction as the
claim state. A process crash therefore cannot commit the retry while losing its operational counter.
Calling `snapshot()` also atomically moves expired running leases to `unknown`, making its gauges
consistent with the ledger's dispatch rules. Repeated snapshots do not double-count that transition.

Counters survive process restarts and terminal claim cleanup. They are operational evidence, not a
billing or security audit log: restoring an older database backup also restores older counter
values. Production monitoring should alert on non-zero exhausted claims and sustained unknown
growth, protect the database against rollback, and scrape the snapshot at a bounded interval.
