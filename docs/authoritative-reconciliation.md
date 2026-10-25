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

`observation_sha256` is a privacy-reduced commitment for correlation: it hashes the idempotency key
and binds the provider ID, request digest, fence, observed time, outcome and canonical output. It is
not an independent signature or proof that the provider told the truth. The HMAC receipt proves
that the configured coordinator authorized a ledger transition; correctness still depends on the
provider adapter reading an authoritative, strongly consistent system of record. The caller must
configure transport authentication, TLS, credentials and the provider's own request timeout.

The elapsed-time check prevents a late response from creating authority, but synchronous Python
cannot cancel an already-blocked provider call. Production adapters should enforce the same timeout
at the network client layer and avoid replicas whose consistency model cannot distinguish committed
from pending work.
