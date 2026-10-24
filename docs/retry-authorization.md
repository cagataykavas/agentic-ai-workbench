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

## Boundary

The signer must derive the no-commit decision from authoritative downstream state; HMAC proves who
issued the decision, not that the decision was correct. Database rollback can also replay old state.
Production systems still need protected keys, durable backups, audit retention, downstream fencing
enforcement and monitoring for long-lived unknown claims.
