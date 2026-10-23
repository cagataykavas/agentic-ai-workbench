from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from src.reconciliation import (
    ReceiptAuthenticationError,
    ReceiptAuthenticator,
    ReconciliationReceipt,
)
from src.sqlite_ledger import (
    ClaimDisposition,
    SQLiteExecutionLedger,
    StaleFencingTokenError,
)

KEY = "write:request-7"
REQUEST_SHA256 = "a" * 64
SECRET_1 = b"a" * 32
SECRET_2 = b"b" * 32


def authenticator(now: list[float], *, signing_key_id: str = "current") -> ReceiptAuthenticator:
    return ReceiptAuthenticator(
        {"previous": SECRET_1, "current": SECRET_2},
        signing_key_id=signing_key_id,
        max_age_seconds=30,
        max_future_skew_seconds=2,
        clock=lambda: now[0],
    )


def unknown_claim(ledger: SQLiteExecutionLedger) -> None:
    claim = ledger.claim_for_request(KEY, REQUEST_SHA256, lease_seconds=30)
    assert claim.disposition is ClaimDisposition.ACQUIRED
    ledger.mark_claim_unknown(KEY, REQUEST_SHA256, claim.fencing_token or 0)


def test_receipt_is_deterministic_and_supports_key_rotation() -> None:
    now = [100.0]
    old_signer = authenticator(now, signing_key_id="previous")
    rotated_verifier = authenticator(now, signing_key_id="current")

    first = old_signer.issue(KEY, REQUEST_SHA256, 1, {"saved": 7, "region": "tr"})
    second = old_signer.issue(KEY, REQUEST_SHA256, 1, {"region": "tr", "saved": 7})

    assert first == second
    assert len(first.signature) == 64
    assert first.output_json == '{"region":"tr","saved":7}'
    assert rotated_verifier.verify(first) == {"region": "tr", "saved": 7}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: replace(receipt, key="write:changed"),
        lambda receipt: replace(receipt, request_sha256="b" * 64),
        lambda receipt: replace(receipt, fencing_token=2),
        lambda receipt: replace(receipt, output_json='{"saved":8}'),
        lambda receipt: replace(receipt, issued_at_ms=99_000),
        lambda receipt: replace(receipt, signature="0" * 64),
    ],
)
def test_modified_signed_fields_are_rejected(mutate) -> None:
    now = [100.0]
    verifier = authenticator(now)
    receipt = verifier.issue(KEY, REQUEST_SHA256, 1, {"saved": 7})

    with pytest.raises(ReceiptAuthenticationError, match="signature is invalid"):
        verifier.verify(mutate(receipt))


def test_stale_and_future_receipts_are_rejected() -> None:
    now = [100.0]
    verifier = authenticator(now)
    receipt = verifier.issue(KEY, REQUEST_SHA256, 1, {"saved": 7})

    now[0] = 131.0
    with pytest.raises(ReceiptAuthenticationError, match="stale"):
        verifier.verify(receipt)

    now[0] = 97.0
    with pytest.raises(ReceiptAuthenticationError, match="future"):
        verifier.verify(receipt)


def test_unknown_key_and_noncanonical_output_are_rejected() -> None:
    now = [100.0]
    verifier = authenticator(now)
    receipt = verifier.issue(KEY, REQUEST_SHA256, 1, {"saved": 7})

    with pytest.raises(ReceiptAuthenticationError, match="unknown"):
        verifier.verify(replace(receipt, key_id="retired"))
    with pytest.raises(ReceiptAuthenticationError, match="not canonical"):
        verifier.verify(replace(receipt, output_json='{ "saved": 7 }'))


def test_authenticator_rejects_weak_keys_and_unbounded_policy() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        ReceiptAuthenticator({"current": b"short"}, signing_key_id="current")
    with pytest.raises(ValueError, match="signing_key_id"):
        ReceiptAuthenticator({"current": SECRET_1}, signing_key_id="missing")
    with pytest.raises(ValueError, match="max_age_seconds"):
        ReceiptAuthenticator(
            {"current": SECRET_1},
            signing_key_id="current",
            max_age_seconds=0,
        )


def test_receipt_output_must_be_finite_and_bounded() -> None:
    verifier = authenticator([100.0])
    with pytest.raises(ReceiptAuthenticationError, match="finite JSON"):
        verifier.issue(KEY, REQUEST_SHA256, 1, {"value": float("nan")})
    with pytest.raises(ReceiptAuthenticationError, match="exceeds"):
        verifier.issue(KEY, REQUEST_SHA256, 1, {"value": "x" * 65_536})


def test_authenticated_receipt_resolves_unknown_claim_without_redispatch(tmp_path) -> None:
    now = [100.0]
    verifier = authenticator(now)
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db", clock=lambda: now[0])
    unknown_claim(ledger)
    receipt = verifier.issue(KEY, REQUEST_SHA256, 1, {"saved": 7})

    ledger.record_authenticated_reconciled_success(receipt, verifier)

    replay = ledger.claim_for_request(KEY, REQUEST_SHA256, lease_seconds=30)
    assert replay.disposition is ClaimDisposition.REPLAYED
    assert replay.output == {"saved": 7}


def test_invalid_receipt_cannot_mutate_unknown_claim(tmp_path) -> None:
    now = [100.0]
    verifier = authenticator(now)
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db", clock=lambda: now[0])
    unknown_claim(ledger)
    receipt = verifier.issue(KEY, REQUEST_SHA256, 1, {"saved": 7})

    with pytest.raises(ReceiptAuthenticationError, match="signature is invalid"):
        ledger.record_authenticated_reconciled_success(
            replace(receipt, output_json='{"saved":8}'),
            verifier,
        )

    claim = ledger.claim_for_request(KEY, REQUEST_SHA256, lease_seconds=30)
    assert claim.disposition is ClaimDisposition.UNKNOWN
    assert ledger.get_for_request(KEY, REQUEST_SHA256) is None


def test_authentic_receipt_for_different_claim_is_rejected(tmp_path) -> None:
    now = [100.0]
    verifier = authenticator(now)
    ledger = SQLiteExecutionLedger(tmp_path / "ledger.db", clock=lambda: now[0])
    unknown_claim(ledger)
    other_receipt = verifier.issue("write:other", REQUEST_SHA256, 1, {"saved": 7})

    with pytest.raises(StaleFencingTokenError, match="changed before reconciliation"):
        ledger.record_authenticated_reconciled_success(other_receipt, verifier)

    claim = ledger.claim_for_request(KEY, REQUEST_SHA256, lease_seconds=30)
    assert claim.disposition is ClaimDisposition.UNKNOWN


def test_concurrent_receipt_delivery_commits_exactly_once(tmp_path) -> None:
    now = [100.0]
    verifier = authenticator(now)
    database = tmp_path / "ledger.db"
    ledger = SQLiteExecutionLedger(database, clock=lambda: now[0])
    unknown_claim(ledger)
    receipt = verifier.issue(KEY, REQUEST_SHA256, 1, {"saved": 7})

    def consume(_delivery: int) -> str:
        try:
            SQLiteExecutionLedger(database, clock=lambda: now[0]).record_authenticated_reconciled_success(
                receipt,
                verifier,
            )
        except StaleFencingTokenError:
            return "rejected"
        return "committed"

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(consume, range(64)))

    assert outcomes.count("committed") == 1
    assert outcomes.count("rejected") == 63
    assert ledger.get_for_request(KEY, REQUEST_SHA256) == {"saved": 7}


def test_receipt_wire_shape_does_not_expose_secret_material() -> None:
    receipt = authenticator([100.0]).issue(KEY, REQUEST_SHA256, 1, {"saved": 7})
    wire = receipt.to_dict()

    assert wire["key_id"] == "current"
    assert wire["output"] == {"saved": 7}
    assert "secret" not in wire
    assert SECRET_2.hex() not in str(wire)
    assert isinstance(receipt, ReconciliationReceipt)
