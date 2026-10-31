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
the promotion result cannot be paired with a different pre-failover observation. CI then runs the
database-free `audit` command over both archived documents. The auditor rejects duplicate or unknown
fields, invalid seals, unsafe types, a different provider or cluster, a substituted preparation
document, a non-advancing timeline or checkpoint, and timestamps that reverse the phase order:

```bash
python tools/postgres_authority_failover_drill.py audit \
  --prepared-evidence postgres-failover-prepared.json \
  --verified-evidence postgres-failover-verified.json
```

The successful output is a key-free digest and transition summary suitable for an artifact intake
gate. The evidence SHA-256 values provide integrity and pairing checks, not trusted provenance: an
attacker able to replace both artifacts can recompute their unkeyed seals. On trusted pushes, CI
therefore issues keyless GitHub artifact attestations for both evidence files after the structural
audit passes. The action is pinned to an immutable commit and receives only `contents: read`,
`id-token: write` and `attestations: write`; no long-lived signing key is stored.

After downloading both files, a consumer with GitHub CLI authentication can require the repository,
signer workflow, source ref and a GitHub-hosted runner before repeating the causal audit:

```bash
python tools/postgres_authority_failover_drill.py verify-attestation \
  --prepared-evidence postgres-failover-prepared.json \
  --verified-evidence postgres-failover-verified.json \
  --repository cagataykavas/agentic-ai-workbench \
  --signer-workflow .github/workflows/ci.yml \
  --source-ref refs/heads/main
```

Verification fails closed if `gh attestation verify` is unavailable, times out or rejects either
file. Pinning `refs/heads/main` is important: repository members can generate attestations from
other trusted-push branches, and provenance authenticates the workflow identity and inputs rather
than proving the database observations were truthful.

For disaster-recovery intake without GitHub API access, download each evidence file's bundle while
online and refresh the trusted root before crossing the air gap. Also record the repository's
numeric ID from the GitHub API; unlike its name, that identifier survives a rename and cannot be
reused by a replacement repository. The verifier requires the complete offline policy and checks
the repository ID in every verified signing certificate:

```bash
gh attestation download postgres-failover-prepared.json \
  --repo cagataykavas/agentic-ai-workbench
gh attestation download postgres-failover-verified.json \
  --repo cagataykavas/agentic-ai-workbench
gh attestation trusted-root > trusted_root.jsonl

python tools/postgres_authority_failover_drill.py verify-attestation \
  --prepared-evidence postgres-failover-prepared.json \
  --verified-evidence postgres-failover-verified.json \
  --repository cagataykavas/agentic-ai-workbench \
  --source-ref refs/heads/main \
  --prepared-bundle sha256:PREPARED_DIGEST.jsonl \
  --verified-bundle sha256:VERIFIED_DIGEST.jsonl \
  --trusted-root trusted_root.jsonl \
  --repository-id 1329851199
```

Transfer the trusted root over a separately controlled channel; a root supplied by the same party
as the evidence is not a trust boundary. Refresh it whenever new signed material is imported.
Offline verification cannot discover repository renames or trust-root revocation after the root was
captured, so the archived repository ID and root acquisition record remain part of the intake
procedure.

This is an integration drill, not a consensus or disaster-recovery claim. The old primary is
process-stopped rather than network-partitioned, promotion is operator-driven, and the topology has
one standby. Production deployments still require an external election authority, split-brain
prevention, credential rotation, durable backup/restore testing and an independently
rollback-protected checkpoint anchor.

