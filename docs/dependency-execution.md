# Dependency-aware tool execution

Agent plans often contain work that can run in parallel and work that must not start until a
prerequisite succeeds. Executing the list in planner order either wastes concurrency or lets a
downstream side effect run after its evidence-producing parent failed.

`src.dag_execution.DependencyExecutor` is a framework-independent execution boundary over the
existing `ToolRegistry`, `ToolPolicy`, and `ExecutionLedger`:

```python
trace = await DependencyExecutor(registry, max_concurrency=4).execute(
    "validate and publish",
    [
        DependencyAction("fetch", "fetch_candidate", {"revision": "v4"}),
        DependencyAction("validate", "validate_candidate", {"revision": "v4"}, ("fetch",)),
        DependencyAction("publish", "publish_candidate", {"revision": "v4"}, ("validate",)),
    ],
    approved_action_ids=frozenset({"publish"}),
)
```

For restart-safe replay on one host, inject the standard-library SQLite adapter:

```python
from src.sqlite_ledger import SQLiteExecutionLedger

executor = DependencyExecutor(
    registry,
    ledger=SQLiteExecutionLedger("execution-ledger.db"),
    claim_lease_seconds=30,
)
```

The adapter stores canonical JSON outputs, preserves the first terminal result for a request, and
uses an immediate transaction to serialize competing commits. A replacement process opening the
same database therefore replays the prior success or rejects a changed request digest without
calling the tool again.

Both the basic governed runtime and this dependency executor construct request identities through
the same strict `CanonicalRequestIdentity` contract. It snapshots JSON arguments, rejects NaN,
infinity, non-object or oversized inputs, and hashes the canonical tool-and-arguments document.
This prevents the two execution paths from disagreeing about whether a persisted result belongs to
a request.

Before upgrading a database that may contain older key-only terminal rows, inspect it without
opening the mutating ledger adapter:

```python
from src.sqlite_ledger import inspect_terminal_bindings

inventory = inspect_terminal_bindings("runtime.db")
print(inventory.as_dict())
```

The inspection uses SQLite read-only/query-only mode and returns counts only: valid bindings,
legacy null bindings and malformed digests. It does not select keys, outputs or request digests,
and it never replays, deletes or upgrades a row. Operators must explicitly quarantine or migrate
every unsafe row before treating the database as request-bound.

The backup-first migration command accepts a private, reviewed mapping for every null-bound
terminal row. Each entry contains the ledger key, canonical tool and arguments, the independently
reviewed request digest, and the SHA-256 of the row's exact stored `output_json` text:

```json
{
  "schema_version": "sqlite-binding-mapping/v1",
  "entries": [
    {
      "key": "write:reviewed-key",
      "tool": "write",
      "arguments": {"value": 7},
      "request_sha256": "<canonical tool-and-arguments SHA-256>",
      "output_sha256": "<stored output_json SHA-256>"
    }
  ]
}
```

Run it offline while no runtime is using the ledger:

```bash
python -m tools.migrate_sqlite_bindings \
  --database runtime.db \
  --mapping reviewed-bindings.json \
  --backup runtime.pre-binding-migration.db \
  --receipt binding-migration-receipt.json
```

The command creates a mode-`0600` SQLite backup before obtaining the migration transaction. It
then requires exact mapping coverage, recomputes every canonical request digest, verifies each
current output digest, rejects malformed or already-bound rows and active claims, and updates only
rows whose binding is still null. The receipt retains only the backup, mapping and aggregate
binding commitments; it excludes keys, arguments and outputs. A failed validation leaves the
source unchanged and preserves the backup for investigation. The mapping and backup are sensitive
operational artifacts and must not be committed.

Before a new idempotent handler starts, the adapter atomically creates a lease and returns a
monotonically increasing fencing token. A handler that writes to a dependency should propagate it:

```python
from src.dag_execution import get_current_fencing_token

async def publish(arguments: dict) -> dict:
    token = get_current_fencing_token()
    return await downstream.put(arguments, fencing_token=token)
```

The downstream system must reject tokens older than the greatest token it has accepted. Local
fencing alone cannot revoke a remote write already in progress.

If the handler raises after dispatch, or the lease expires before a trusted terminal result is
recorded, the claim becomes `unknown`. An ordinary retry receives
`idempotency_outcome_unknown` and does not call the tool. Reconciliation is intentionally explicit:

- `record_reconciled_success(...)` persists a verified remote receipt without redispatch; or
- `retry_unknown_claim(...)` records an operator decision that no side effect committed and issues
  the next fencing token.

Production callers can replace the unauthenticated operator path with
`retry_unknown_claim_authenticated(...)`. Its HMAC receipt binds the idempotency key, request
digest, current fencing token, issue time, signing key and bounded next-lease duration. Verification
happens before the transaction; the transaction then advances the exact unknown claim only once.

Both operations require the request digest and current token, so a stale reconciler cannot replace
a newer decision.

## Guarantees

- The complete graph, tool catalog, JSON argument snapshot, identifiers, dependency budgets, and
  idempotency keys are validated before any handler starts.
- Cycles, missing dependencies, unknown tools, duplicate action IDs, and excessive graph size fail
  closed with zero handler calls.
- Only succeeded or safely replayed parents unlock a dependant. Failure, denial, missing approval,
  or another blocked dependency propagates without invoking downstream handlers.
- Independent ready actions run with a hard concurrency bound. Results remain in declared plan
  order regardless of completion order.
- Duplicate keys for idempotent actions under the same tool contract are rejected before parallel
  dispatch, closing the race in which both calls observe an empty ledger and repeat the same side
  effect. Ledger keys are namespaced by tool so one contract cannot replay another tool's result.
- Each successful ledger entry also binds the key to the canonical tool-and-arguments SHA-256.
  Reusing a key with changed arguments fails closed before dispatch within one plan and before stale
  replay across later executions; equivalent JSON objects with reordered keys still replay safely.
- Arguments are canonicalized and copied at admission, preventing caller mutation after validation.
- Synchronous handlers run off the event loop; asynchronous handlers are supported directly.
- SQLite-backed idempotent actions acquire a transactionally serialized claim before dispatch;
  competitors receive a bounded busy result and do not invoke the handler.
- Lease expiry and post-dispatch handler errors stop at an explicit unknown-outcome boundary rather
  than silently repeating a possibly committed side effect.
- Fenced completion requires the active request digest and fencing token. Validation failures
  release their claim because the handler has not started.
- Caller cancellation is not reported until the active wave reaches a terminal state, avoiding an
  abandoned in-process call whose outcome is unknown to the ledger.
- Traces bind the task and admitted plan with SHA-256 identities and expose bounded error classes,
  not exception messages.

## Operational boundary

This scheduler and its concurrency limit are in-process. `SQLiteExecutionLedger` coordinates claims
and terminal commits on one host, but it does not make a remote side effect and the local ledger one
atomic transaction. A crash can still strand a committed remote effect before its receipt is
recorded. Fencing is effective only when the downstream system enforces the token; otherwise the
unknown-outcome gate prevents automatic replay but cannot undo or prove a remote commit. Production
tools therefore still need downstream idempotency keys, transport deadlines, authenticated
receipts, reconciliation and a distributed coordinator when execution spans hosts or regions.

This migration authenticates operator-reviewed associations; it cannot reconstruct or prove the
request that originally produced a legacy result. SQLite remains a single-host reference adapter,
not a distributed coordinator.

