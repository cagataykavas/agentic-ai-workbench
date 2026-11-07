from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from src.runtime_eval_checkpoint_key_status import (
    GENESIS_STATUS_SHA256,
    STATUS_SCHEMA,
    RuntimeBenchmarkCheckpointKeyStatusError,
    create_checkpoint_key_status,
    load_checkpoint_key_status,
    verify_checkpoint_key_status,
)

CHECKPOINT_KEY = b"0" * 44
CHECKPOINT_KEY_SHA256 = hashlib.sha256(CHECKPOINT_KEY).hexdigest()
CHECKPOINT_KEY_ID = "runtime-benchmark-history-2026-11"
AUTHORITY_KEY = b"1" * 44
AUTHORITY_KEY_SHA256 = hashlib.sha256(AUTHORITY_KEY).hexdigest()
AUTHORITY_KEY_ID = "runtime-benchmark-key-status-2026-11"
SIGNATURE = b"s" * 64
ISSUED_AT = "2026-11-07T06:00:00Z"
EXPIRES_AT = "2026-11-07T18:00:00Z"
VERIFICATION_TIME = "2026-11-07T07:00:00Z"


def status(**overrides: object) -> dict[str, object]:
    parameters = {
        "checkpoint_key_id": CHECKPOINT_KEY_ID,
        "checkpoint_public_key_sha256": CHECKPOINT_KEY_SHA256,
        "state": "active",
        "generation": 1,
        "previous_status_sha256": GENESIS_STATUS_SHA256,
        "status_authority_key_id": AUTHORITY_KEY_ID,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "authority_public_key_der": AUTHORITY_KEY,
        "signer": lambda message: SIGNATURE if message else b"",
    }
    parameters.update(overrides)
    return create_checkpoint_key_status(**parameters)


def verify(document: object, **overrides: object) -> dict[str, object]:
    parameters = {
        "expected_checkpoint_key_id": CHECKPOINT_KEY_ID,
        "expected_checkpoint_public_key_sha256": CHECKPOINT_KEY_SHA256,
        "expected_generation": 1,
        "expected_previous_status_sha256": GENESIS_STATUS_SHA256,
        "expected_status_authority_key_id": AUTHORITY_KEY_ID,
        "expected_status_authority_public_key_sha256": AUTHORITY_KEY_SHA256,
        "verification_time": VERIFICATION_TIME,
        "signature_verifier": lambda public_key, signature, message: (
            public_key == AUTHORITY_KEY and signature == SIGNATURE and bool(message)
        ),
    }
    parameters.update(overrides)
    return verify_checkpoint_key_status(document, **parameters)


def test_verifies_active_generation_and_emits_private_receipt() -> None:
    document = status()
    receipt = verify(document)

    assert document["status"]["schema_version"] == STATUS_SCHEMA
    assert receipt["checkpoint_key_status_generation"] == 1
    assert receipt["checkpoint_key_status_previous_sha256"] == GENESIS_STATUS_SHA256
    assert receipt["checkpoint_key_status_valid_until"] == EXPIRES_AT
    assert receipt["checkpoint_key_status_authority_sha256"] == AUTHORITY_KEY_SHA256
    assert len(receipt["checkpoint_key_status_sha256"]) == 64
    serialized = json.dumps(receipt, sort_keys=True)
    assert CHECKPOINT_KEY_ID not in serialized
    assert AUTHORITY_KEY_ID not in serialized
    assert document["signature"]["value"] not in serialized
    assert document["authority_public_key"]["value"] not in serialized


def test_rejects_revoked_checkpoint_key() -> None:
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="key_revoked"):
        verify(status(state="revoked"))


def test_generation_and_predecessor_bind_rotation() -> None:
    predecessor = hashlib.sha256(b"generation-one").hexdigest()
    rotated = status(generation=2, previous_status_sha256=predecessor)
    receipt = verify(
        rotated,
        expected_generation=2,
        expected_previous_status_sha256=predecessor,
    )
    assert receipt["checkpoint_key_status_generation"] == 2

    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="binding_mismatch"):
        verify(rotated)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        (
            {"expected_status_authority_public_key_sha256": "f" * 64},
            "authority_key_mismatch",
        ),
        ({"expected_status_authority_key_id": "replacement"}, "binding_mismatch"),
        ({"expected_checkpoint_key_id": "replacement"}, "binding_mismatch"),
        (
            {"expected_checkpoint_public_key_sha256": "e" * 64},
            "binding_mismatch",
        ),
    ],
)
def test_rejects_authority_or_checkpoint_key_substitution(override: dict[str, object], message: str) -> None:
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match=message):
        verify(status(), **override)


@pytest.mark.parametrize(
    ("verification_time", "message"),
    [
        ("2026-11-07T05:59:59Z", "not_yet_valid"),
        (EXPIRES_AT, "expired"),
        ("2026-11-08T00:00:00Z", "expired"),
    ],
)
def test_rejects_status_outside_validity_window(verification_time: str, message: str) -> None:
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match=message):
        verify(status(), verification_time=verification_time)


def test_rejects_invalid_predecessor_lifetime_and_key_role_reuse() -> None:
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="predecessor"):
        status(generation=2, previous_status_sha256=GENESIS_STATUS_SHA256)
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="lifetime"):
        status(expires_at="2026-11-08T06:00:01Z")
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="role_reuse"):
        status(
            checkpoint_public_key_sha256=AUTHORITY_KEY_SHA256,
            authority_public_key_der=AUTHORITY_KEY,
        )


def test_signature_is_checked_before_untrusted_status_semantics() -> None:
    document = copy.deepcopy(status())
    document["status"]["state"] = "unknown"
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="signature_invalid"):
        verify(document, signature_verifier=lambda *_: False)


def test_rejects_unknown_fields_noncanonical_base64_and_bad_signature() -> None:
    document = status()
    document["unexpected"] = True
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="envelope_schema"):
        verify(document)

    document = status()
    document["authority_public_key"]["value"] += "\n"
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="authority_key_invalid"):
        verify(document)

    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="signature_invalid"):
        verify(status(), signature_verifier=lambda *_: False)


def test_loader_rejects_duplicate_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"status":{},"status":{}}', encoding="utf-8")
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="duplicate"):
        load_checkpoint_key_status(duplicate)

    target = tmp_path / "status.json"
    target.write_text(json.dumps(status()), encoding="utf-8")
    link = tmp_path / "status-link.json"
    link.symlink_to(target)
    with pytest.raises(RuntimeBenchmarkCheckpointKeyStatusError, match="file_unavailable"):
        load_checkpoint_key_status(link)
