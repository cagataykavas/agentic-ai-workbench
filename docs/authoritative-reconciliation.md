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
- `not_committed` must not contain output and produces one bounded retry authorization;
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
  "observed_at_ms": 100000,
  "outcome": "committed",
  "output": {"payment_id": "p-7"},
  "provider_id": "payments-primary",
  "request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "schema_version": 1
}
```

The adapter limits the streamed read even when `Content-Length` is absent or dishonest. It rejects
oversized bodies, compression, duplicate JSON fields, invalid UTF-8, non-finite numbers, unknown or
missing fields, malformed identities and unsupported outcomes. It does not copy an upstream body or
transport diagnostic into its stable error text. The coordinator then performs the security-relevant
echo, freshness and outcome/output consistency checks before granting authority.

`observation_sha256` is a privacy-reduced commitment for correlation: it hashes the idempotency key
and binds the provider ID, request digest, fence, observed time, outcome and canonical output. It is
not an independent signature or proof that the provider told the truth. The HMAC receipt proves
that the configured coordinator authorized a ledger transition; correctness still depends on the
provider adapter reading an authoritative, strongly consistent system of record. Certificate and
private-key files must come from the deployment's secret mount and be rotated outside this library;
the repository contains no credential material.

The elapsed-time check prevents a late response from creating authority, but synchronous Python
cannot cancel an already-blocked provider call. Production adapters should enforce the same timeout
at the network client layer; the included HTTP adapter does so for connect/read operations. Python's
synchronous socket API still cannot be force-cancelled from another thread. The adapter also cannot
prove that the remote service used a strongly consistent read, so deployments must keep the endpoint
off eventual-consistency replicas and test ambiguous commits and replica lag against a real sandbox.
