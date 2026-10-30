# Authenticated retry authorization

An unknown tool outcome has two legitimate resolutions:

1. the remote side effect committed, so its authenticated success receipt becomes the terminal
   ledger result; or
2. authoritative reconciliation proves that nothing committed, so one new fenced attempt may run.

Treating the second decision as an ordinary method call leaves a production authority gap. Anyone
who can reach that call path can reopen an irreversible operation after a timeout. This reference
contract requires a short-lived HMAC-SHA256 authorization before the SQLite ledger advances the
claim.

## Signed fields

`RetryAuthorizationReceipt` binds:

- a domain separator (`retry_authorization`) and schema version;
- the idempotency key and canonical request SHA-256;
- the exact unknown fencing token;
- a bounded lease duration for the next owner;
- issue time and rotation key ID.

The receipt never carries secret material. The verifier supports a small rotation keyring, rejects
weak keys, unknown key IDs, stale/future timestamps, invalid identities, malformed leases and any
edited signed field. The domain separator prevents a success receipt from being interpreted as a
retry authorization.

## Consumption contract

```python
authorization = authenticator.issue_retry_authorization(
    key="write:request-7",
    request_sha256=request_digest,
    fencing_token=1,
    lease_seconds=30,
)
claim = ledger.retry_unknown_claim_authenticated(authorization, authenticator)
assert claim.fencing_token == 2
```

Verification occurs before `BEGIN IMMEDIATE`. Inside the transaction, the ledger requires the same
key, request digest, fencing token and `unknown` state before advancing to `running`. Concurrent or
replayed deliveries therefore produce one owner and stale-token failures for the rest.

Each new claim also persists an immutable `retry_limit` and an atomically incremented
`retry_count`. The creator's `max_retry_attempts` policy applies for the claim's full lifetime;
reopening the database with a more permissive process configuration cannot raise it. Once consumed,
even an otherwise valid signed authorization fails closed with `RetryBudgetExhaustedError` and the
claim remains `unknown` for operator reconciliation. Existing databases are migrated with a
conservative three-retry limit.

```python
ledger = SQLiteExecutionLedger("agent.db", max_retry_attempts=2)
```

## Boundary

The coordinator requires every `not_committed` observation to carry an authority epoch plus applied
durable sequence and replica-acknowledgement count. A deployment policy must require a current epoch
and at least one safe sequence or replica threshold before the signer issues this receipt. Those
fields are bound into the observation digest, while the compact retry receipt remains the consumable
claim/lease authority.

The signer must still derive the proof from authoritative downstream state; HMAC proves who issued
the decision, not that the datastore metadata was truthful. Database rollback can also replay old state.
Production systems still need protected keys, durable backups, audit retention, downstream fencing
enforcement and monitoring for long-lived or budget-exhausted unknown claims. The retry limit is
per idempotency claim, not a global rate limiter or downstream circuit breaker.

## PostgreSQL failover drill

CI also exercises `PostgresAuthorityCheckpointStore` against a disposable PostgreSQL 17
primary/standby pair. The drill waits for a synchronous streaming replica, writes generation 1,
and proves the exact checkpoint is readable on the hot standby. It then stops the old primary,
promotes the standby onto a higher timeline, verifies the cluster identity and recovered head, and
advances generation 2 with the pre-failover digest as the CAS condition. A successful old-primary
connection fails the drill before the promoted writer is allowed to advance.

The two phases exchange sealed, bounded JSON evidence containing only checkpoint digests, a hashed
system identifier, timelines, epochs and boolean assertions. DSNs, passwords, signing material and
raw checkpoint documents are excluded. The final artifact binds the preparation artifact digest so
the promotion result cannot be paired with a different pre-failover observation.

This is an integration drill, not a consensus or disaster-recovery claim. The old primary is
process-stopped rather than network-partitioned, promotion is operator-driven, and the topology has
one standby. Production deployments still require an external election authority, split-brain
prevention, credential rotation, durable backup/restore testing and an independently
rollback-protected checkpoint anchor.
