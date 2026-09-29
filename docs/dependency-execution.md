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
- Arguments are canonicalized and copied at admission, preventing caller mutation after validation.
- Synchronous handlers run off the event loop; asynchronous handlers are supported directly.
- Caller cancellation is not reported until the active wave reaches a terminal state, avoiding an
  abandoned in-process call whose outcome is unknown to the ledger.
- Traces bind the task and admitted plan with SHA-256 identities and expose bounded error classes,
  not exception messages.

## Operational boundary

This scheduler is in-process. Its ledger and concurrency limit are not shared across replicas, and
waiting for a synchronous thread does not stop that thread. A crashed process can still strand a
remote side effect between commit and ledger recording. Production tools need downstream
idempotency keys, transport deadlines, authenticated receipts, durable execution state, and the
reconciliation workflow described elsewhere in this repository. The scheduler also treats declared
dependencies as policy input; it cannot discover a planner's omitted data or side-effect dependency.

The next production step is a durable adapter that claims ready DAG nodes transactionally, fences
workers with leases, and records each terminal result before unlocking children across replicas.
