# Agent plan execution binding

An agent plan is reviewed against a particular tool registry and policy. If a tool
description, risk classification, argument schema or policy changes before dispatch,
executing the old plan creates a time-of-check/time-of-use gap.

`src.plan_binding` issues a short-lived receipt over:

- the exact task and ordered `PlannedAction` content;
- every registered tool's planner-facing description, risk, side-effect and
  idempotency metadata;
- a server-owned contract version and canonical argument-schema SHA-256;
- the active deny and human-approval policy;
- issuance, expiry and action-count bounds.

The task and arguments are represented only by canonical SHA-256 identities in the
receipt and admission report. Immediately before dispatch, `execute_bound_plan`
recomputes every identity from the live runtime. Drift or expiry raises
`PlanBindingError` before any handler is called.

```python
receipt = bind_plan(
    task=task,
    plan=plan,
    registry=runtime.registry,
    policy=runtime.policy,
    contracts=server_owned_contracts,
    issued_at=now,
    ttl_seconds=300,
)

trace = execute_bound_plan(
    runtime,
    receipt=receipt,
    task=task,
    plan=plan,
    contracts=server_owned_contracts,
    now=dispatch_time,
)
```

## Fail-closed boundaries

Plans are limited to 128 actions and 128 KiB of canonical JSON with explicit depth
and node budgets. Duplicate action IDs, unknown tools, incomplete contract catalogs,
cycles, non-string object keys and non-finite values are rejected. TTL is constrained
to 30–3,600 seconds, timestamps must be timezone-aware and future skew is bounded.

This mechanism establishes consistency, not authenticity. The receipt is
content-addressed but unsigned; a process or datastore attacker who can replace both
the plan and receipt remains out of scope. Handler code is deliberately not hashed
because Python callable serialization is not stable: deployments must increment the
server-owned contract version whenever handler semantics change.

Human approval is still evaluated by `GovernedAgentRuntime`; this receipt does not
authenticate an approver. The next step is to sign the receipt with a KMS-backed key,
persist it with the planner trace and require its digest in the tool-dispatch ledger.
