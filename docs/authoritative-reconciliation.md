# Authoritative downstream reconciliation

An expired or failed tool call has an `unknown` outcome: retrying it blindly can duplicate a side
effect, while assuming success can lose work. `AuthoritativeReconciliationCoordinator` turns one
bounded lookup against the system of record into the existing authenticated ledger protocol.

```python
query = ReconciliationQuery(
    key="payment:request-7",
    request_sha256=request_sha256,
    fencing_token=1,
)
decision = coordinator.reconcile(query, retry_lease_seconds=15)

if isinstance(decision.receipt, ReconciliationReceipt):
    ledger.record_authenticated_reconciled_success(
        decision.receipt,
        receipt_authenticator,
    )
elif isinstance(decision.receipt, RetryAuthorizationReceipt):
    ledger.retry_unknown_claim_authenticated(
        decision.receipt,
        receipt_authenticator,
    )
# A pending decision contains no receipt and grants no execution authority.
```

The provider must echo the exact idempotency key, canonical request digest and fencing token. The
coordinator also validates the configured provider identity, observation freshness, response shape,
JSON bounds and lookup deadline before it signs anything:

- `committed` requires the authoritative output and produces a success receipt;
- `not_committed` must not contain output, must carry a negative durability proof that satisfies the
  configured epoch plus durable-sequence or replica threshold, and only then produces one bounded
  retry authorization;
- `pending` must not contain output and produces no receipt.

Identity mismatch, stale/future observations, contradictory output, malformed responses, provider
exceptions and late responses all fail closed as `authoritative_reconciliation_unavailable`.
Provider exception text is retained only as the Python exception cause; it is not copied into the
stable public error message.

## Bounded mTLS JSON adapter

`MtlsJsonStatusProvider` is a concrete standard-library adapter for a system-of-record endpoint. It
builds its own client context from an explicit CA bundle, client certificate and private-key path;
the public constructor does not accept an arbitrary unauthenticated transport context.

```python
from src.http_reconciliation_provider import MtlsJsonStatusProvider
from src.reconciliation_adapter import NegativeObservationPolicy

provider = MtlsJsonStatusProvider(
    provider_id="payments-primary",
    endpoint="https://payments.internal/v1/reconciliation",
    ca_file="/run/secrets/payments-ca.pem",
    cert_file="/run/secrets/reconciler-client.pem",
    key_file="/run/secrets/reconciler-client-key.pem",
)

coordinator = AuthoritativeReconciliationCoordinator(
    provider,
    receipt_authenticator,
    negative_observation_policy=NegativeObservationPolicy(
        minimum_authority_epoch=42,
        minimum_durable_sequence=9182,
        required_replica_acknowledgements=1,
    ),
    lookup_timeout_seconds=0.5,
)
```

The adapter sends one canonical `POST` document:

```json
{
  "fencing_token": 1,
  "key": "payment:request-7",
  "request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "schema_version": 1
}
```

The fixed endpoint may not contain user info, a query or a fragment, so claim data cannot be routed
through caller-controlled URL components. The same coordinator timeout is applied to the HTTPS
connection. Redirects are not followed. The request asks intermediaries not to cache the result and
closes the connection after each lookup.

A successful response must be HTTP 200 with `application/json`, identity content encoding and
exactly these fields:

```json
{
  "fencing_token": 1,
  "key": "payment:request-7",
  "negative_proof": null,
  "observed_at_ms": 100000,
  "outcome": "committed",
  "output": {"payment_id": "p-7"},
  "provider_id": "payments-primary",
  "request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "schema_version": 2
}
```

A negative response uses the same strict response schema and replaces `negative_proof` with the
storage position that established absence:

```json
{
  "authority_epoch": 42,
  "durable_sequence": 9182,
  "replica_acknowledgements": 0
}
```

The policy always requires `authority_epoch` to meet its minimum. It then accepts either a durable
sequence at or beyond the caller's known safe watermark or the configured count of replicas that
observed absence at the same sequence. Requiring the policy explicitly prevents an integration from
silently reverting to trust-on-first-negative behavior. A missing, malformed, stale-epoch or
below-threshold proof fails closed before a retry receipt is signed.

The adapter limits the streamed read even when `Content-Length` is absent or dishonest. It rejects
oversized bodies, compression, duplicate JSON fields, invalid UTF-8, non-finite numbers, unknown or
missing fields, malformed identities and unsupported outcomes. It does not copy an upstream body or
transport diagnostic into its stable error text. The coordinator then performs the security-relevant
echo, freshness, outcome/output consistency and negative-proof policy checks before granting
authority.

`observation_sha256` is a privacy-reduced commitment for correlation: it hashes the idempotency key
and binds the provider ID, request digest, fence, observed time, outcome, canonical output and
negative durability proof. It is not an independent signature or proof that the provider told the
truth. The HMAC receipt proves
that the configured coordinator authorized a ledger transition; correctness still depends on the
provider adapter reading an authoritative, strongly consistent system of record. Certificate and
private-key files must come from the deployment's secret mount and be rotated outside this library;
the repository contains no credential material.

The elapsed-time check prevents a late response from creating authority, but synchronous Python
cannot cancel an already-blocked provider call. Production adapters should enforce the same timeout
at the network client layer; the included HTTP adapter does so for connect/read operations. Python's
synchronous socket API still cannot be force-cancelled from another thread. The adapter also cannot
prove that the remote service reported a truthful epoch, sequence or replica count. Deployments must
derive those fields from protected datastore metadata, keep policy watermarks current and test
ambiguous commits and replica lag against the real persistence system.

## PostgreSQL primary/WAL adapter

`PostgresWalStatusProvider` removes the remote service's ability to invent negative-proof fields.
It reads the claim, controller-owned authority epoch and durable sequence, PostgreSQL recovery role,
local WAL flush position, and synchronous-replica replay state in one `REPEATABLE READ READ ONLY`
transaction. Install the optional driver with `agentic-ai-workbench[postgres]`:

```python
from src.postgres_reconciliation_provider import PostgresWalStatusProvider

provider = PostgresWalStatusProvider(
    provider_id="payments-postgres",
    dsn=postgres_dsn_from_secret_manager,
    schema="agent_runtime",
)
```

The adapter expects two application-owned tables. Use migrations and database roles to prevent the
reconciliation identity from modifying them:

```sql
CREATE TABLE agent_runtime.agent_reconciliation_authority (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    authority_epoch bigint NOT NULL CHECK (authority_epoch > 0),
    durable_sequence bigint NOT NULL CHECK (durable_sequence >= 0),
    minimum_wal_lsn pg_lsn NOT NULL
);

CREATE TABLE agent_runtime.agent_reconciliation_claims (
    idempotency_key text PRIMARY KEY,
    request_sha256 text NOT NULL,
    fencing_token bigint NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'committed')),
    output jsonb
);
```

The downstream writer must serialize claim commits with the singleton authority row and advance
`durable_sequence` in the same transaction. The failover controller advances `authority_epoch` and
sets `minimum_wal_lsn` to the WAL position every promoted primary must contain. The adapter rejects
standbys, missing or duplicate authority state, a local flush LSN below that watermark, malformed
claim identity/state, and ambiguous database responses. A missing claim produces `not_committed`
only after these checks. Synchronous acknowledgements count only `sync`/`quorum` replicas whose
`replay_lsn` has reached the controller watermark.

Identifiers are restricted before being interpolated; the idempotency key remains a query
parameter. Statement and idle-in-transaction deadlines are applied from the coordinator's lookup
budget. Database/DSN diagnostics are retained only as exception causes and are not copied into the
stable public error. The CI contract runs the provider against a real PostgreSQL primary in addition
to fail-closed protocol tests.

### Bounded provider observability

`metrics_snapshot()` returns a thread-safe, fixed-cardinality view that can be translated directly
into metrics without turning claim or topology data into labels:

```python
metrics = provider.metrics_snapshot().as_dict()
emit_metrics(metrics)
```

The snapshot contains total/successful lookups, fixed outcome counts, eight stable rejection
counts, the latest positive/negative WAL margin and the minimum margin observed since process start. `wal_ready`
is `true` at or above the controller watermark, `false` below it, and `null` until a parseable primary
snapshot has supplied both LSNs. The margin is the byte difference between the local flush position
and required minimum; raw LSNs are never retained or emitted.

Rejection reasons are bounded to `not_primary`, `wal_watermark_not_reached`, `malformed_snapshot`,
`malformed_authority`, `missing_or_ambiguous`, `claim_identity_mismatch`,
`claim_state_malformed`, and `database_error`. Arbitrary PostgreSQL diagnostics cannot create metric
labels. The snapshot also omits DSNs, provider IDs, claim keys, request hashes, fencing tokens,
authority values and replica identities/counts. Copies are immutable, while counters and readiness
gauges update under one process-local lock so concurrent lookups are not lost.

These counters reset when the process restarts and do not replace durable audit receipts. Alert on
non-zero watermark/not-primary rejection rates and negative WAL margin, but do not bypass the gate to
restore availability. Exporters should preserve the fixed reason set rather than adding exception
messages as labels.

### Rollback-protected controller epoch

A static `NegativeObservationPolicy.minimum_authority_epoch` can become stale when a long-running
process survives failover. `SignedAuthorityEpochSource` closes that process-configuration gap by
reloading a signed checkpoint immediately before each `not_committed` observation can authorize a
retry:

```python
from src.authority_epoch_checkpoint import SignedAuthorityEpochSource
from src.postgres_authority_checkpoint_store import PostgresAuthorityCheckpointStore

checkpoint_store = PostgresAuthorityCheckpointStore(
    provider_id="payments-postgres",
    dsn=controller_database_dsn,
    schema="agent_control",
)

epoch_source = SignedAuthorityEpochSource(
    provider_id="payments-postgres",
    checkpoint_loader=checkpoint_store.load,
    keyring=checkpoint_verification_keys,
)
coordinator = AuthoritativeReconciliationCoordinator(
    provider,
    authenticator,
    negative_observation_policy=negative_policy,
    authority_epoch_source=epoch_source,
)
```

The loader must return `(checkpoint_json, anchored_sha256)` from one strongly consistent control-
plane read. The checkpoint binds the provider, monotonic generation, minimum accepted authority
epoch, issue time and key ID under domain-separated HMAC-SHA256. The source rejects an anchor
mismatch, invalid or retired key, stale/future document, generation regression and same-generation
equivocation, and a minimum-epoch decrease even under a higher generation. Its digest is included in
the privacy-reduced observation commitment.

The checkpoint is read only for negative decisions; committed evidence can still resolve an unknown
claim when the controller store is unavailable. Advancing the externally anchored checkpoint from
epoch 1 to epoch 2 immediately prevents an unchanged process policy and epoch-1 database snapshot
from issuing retry authority. Rolling back the JSON while retaining the epoch-2 anchor also fails
closed.

HMAC authenticity is not rollback protection by itself. The control-plane store must provide the
head digest atomically with the document and protect that digest against rollback. The in-process
generation watermark only detects regression during one process lifetime. The source does not
allocate epochs, promote PostgreSQL, fence a former primary or implement distributed consensus.

`PostgresAuthorityCheckpointStore` supplies the missing atomic storage contract for deployments
that use a dedicated PostgreSQL control plane. Operators create the schema, call `initialize()`
under a migration role, and grant runtime readers only `SELECT`. A controller advances canonical
signed checkpoints with `compare_and_swap(checkpoint_json, expected_sha256=previous_head)` under a
serializable transaction, provider-scoped advisory lock and row lock. The store rejects stale heads,
generation reuse, epoch regression, non-canonical documents and corrupted rows; an exact retry is
idempotent. `load()` reads
the document and digest from one repeatable-read snapshot, so it can be passed directly to
`SignedAuthorityEpochSource`.

The store deliberately does not hold signing keys or validate HMAC authenticity; the signed source
retains that responsibility, while PostgreSQL roles authorize mutation. Its live CI contract uses a
real PostgreSQL 17 service to prove initialization, CAS advancement, stale-writer rejection,
idempotence, corruption detection and end-to-end epoch-source loading. This is a strongly consistent
anchor, not an independent rollback oracle: restoring the control-plane database behind all readers
can still restore an old head. Protected backups or an external monotonic anchor remain required.

This adapter does not turn PostgreSQL streaming replication into consensus. Correctness still
depends on the writer serialization rule, a rollback-protected controller epoch, a trustworthy
minimum WAL watermark, downstream fencing enforcement, and PostgreSQL role permissions. A WAL
watermark rejection should increment a low-cardinality readiness alert; it must not be bypassed to
restore availability. The adapter does not perform promotion or mutate controller state.

## Disposable live-mTLS sandbox

`tools.mtls_reconciliation_sandbox.MtlsReconciliationSandbox` provides a loopback-only HTTPS
system-of-record endpoint for integration tests. It requires a CA-signed client certificate, exposes
the peer certificate common name in its captured request evidence, echoes the exact claim identity,
and can delay a committed response until after the client deadline. Certificates are generated in a
temporary directory during the test run; no keys or certificate artifacts are committed.

The CI integration contract proves three security-relevant paths with real sockets and OpenSSL:

- a trusted server certificate and required client certificate complete a mutual-TLS handshake,
  after which the provider accepts one exact authoritative observation;
- a CA-signed certificate restricted to server authentication is rejected when presented as the
  client identity, before the request reaches the handler;
- the sandbox can observe a request before delaying its reply past the socket timeout, and the
  provider returns no success or retry authority for that ambiguous result.

## Replicated-state failover experiment

`tools.replicated_status_model.ReplicatedStatusModel` can back the same live-mTLS endpoint with a
deterministic primary and replica. A commit becomes visible on the primary immediately, while
`replicate_all()` is the only event that advances the replica. `promote_replica()` then discards
primary-only records, reproducing a stale promotion without sleeps, process races or an external
database.

The model makes two materially different policies executable:

1. A local acknowledgement (`required_replica_acknowledgements=0`) returns evidence immediately.
   Promotion before replication loses the record, so the authoritative lookup reports
   `not_committed`. Turning that negative observation into retry authority could duplicate the
   already-performed external side effect.
2. A replica-gated acknowledgement (`required_replica_acknowledgements=1`) fails closed until the
   record reaches the replica. Repeating the commit with the same cryptographic operation token is
   idempotent, returns the original sequence, and survives promotion.

Commit evidence contains the authority epoch, sequence, acknowledged-replica count and only a
SHA-256 commitment to the operation token. A different token or output cannot take over an existing
claim identity. Tests exercise both policies through the real TLS adapter, so transport and storage
fault boundaries are evaluated together.

Negative model observations expose the current authority epoch, the promoted primary's applied
sequence and whether the replica independently confirms absence at that exact sequence. The live
mTLS integration test demonstrates that a stale promotion produces `(epoch=2, sequence=0,
replica_acknowledgements=0)` and that a coordinator requiring durable sequence `1` issues no retry
authority. The same proof is included in the privacy-reduced observation digest for audit
correlation.

This remains a deterministic two-node state model, not a consensus implementation.
It does not simulate split brain, replica persistence, partial log replay, network reordering or
quorum membership changes. Production deployments must validate the chosen datastore's actual
durability and promotion rules. The PostgreSQL adapter above closes the metadata-derivation gap for
one documented schema, exports bounded readiness metrics and can consume the externally anchored
controller epoch described above. A next increment should exercise checkpoint advancement and
stale-primary fencing in a disposable PostgreSQL failover topology.
