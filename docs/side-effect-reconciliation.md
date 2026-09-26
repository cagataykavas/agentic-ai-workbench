# Side-effect reconciliation audit

An agent can time out after a remote system commits a write but before the worker durably records
success. Retrying blindly can duplicate the side effect; treating the call as failed can hide work
that already happened. `src/side_effect_reconciliation.py` audits the evidence needed to make that
boundary explicit.

## Evidence contract

The JSON artifact binds every call to:

- a canonical intent SHA-256 and, for writes, an idempotency-key SHA-256;
- an effect class: `none`, `idempotent`, `compensatable`, or `irreversible`;
- runtime state, attempt time, finish time, and lease expiry;
- downstream receipts for commits, rejections, and compensations;
- remote operation digests so multiple committed operations can be distinguished.

Raw arguments, outputs, customer IDs, tool errors, and idempotency keys are deliberately absent.
Reports contain only aggregate counts, stable finding/action codes, canonical artifact/policy digests,
and one-way call identifiers.

The parser fails closed on duplicate JSON fields, unknown or missing fields, non-UTF-8 input,
non-finite values, naive/non-UTC timestamps, broken chronology, digest mismatches, duplicate IDs,
orphan compensation, and configurable byte/call/receipt budgets.

## Decision model

| Evidence | Stable action |
|---|---|
| Lease still active | `wait` |
| Idempotent write stranded without a receipt | `retry_same_key` |
| Commit exists but runtime did not acknowledge it | `mark_succeeded` |
| Downstream rejection exists but runtime did not acknowledge it | `mark_failed` |
| Compensatable write committed before failure | `compensate` |
| Non-idempotent write has no authoritative receipt | `query_then_escalate` |
| Duplicate or irreversible ambiguous effect | `escalate` |

A report is `clean` only when no reconciliation action remains. Findings produce a policy-rejection
exit rather than being silently repaired: the audit is evidence analysis, not an executor with
permission to mutate durable agent state or an external system.

## Example

```bash
python -m src.side_effect_reconciliation evidence.json \
  --as-of 2026-09-26T20:00:00Z \
  --output reconciliation-report.json
```

Exit codes are stable for automation:

- `0`: evidence is valid and clean;
- `2`: evidence is valid but reconciliation is required;
- `3`: malformed/untrusted evidence or I/O failure.

Output files are replaced atomically after flush and `fsync`, so a killed audit cannot leave a
partially written report at the requested path.

## Operational limits

This audit does **not** prove that the remote system is truthful. Receipt collectors must be
authenticated, authorized, and durably coupled to the downstream operation. SHA-256 binding detects
accidental or adversarial substitution only when the producer itself is trustworthy.

Compensation is domain-specific and is rarely a literal rollback: refunding a payment does not erase
the original charge, and sending a correction does not unsend an email. The tool therefore verifies
evidence and recommends a bounded action; it does not claim semantic restoration.

For irreversible or non-idempotent writes without an authoritative receipt, the correct response is
operator escalation after querying the source system—not an automatic retry. A production integration
should persist the resulting state transition transactionally, fence concurrent reconcilers, sign or
MAC receipts, and correlate the audit digest with traces and the durable execution ledger.
