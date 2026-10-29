from __future__ import annotations

import json
from dataclasses import replace

import pytest

from src.authority_epoch_checkpoint import (
    AuthorityEpochCheckpointError,
    SignedAuthorityEpochSource,
    dump_authority_epoch_checkpoint,
    load_authority_epoch_checkpoint,
    sign_authority_epoch_checkpoint,
)

SECRET = b"checkpoint-signing-key-material-0001"
NEW_SECRET = b"checkpoint-signing-key-material-0002"
NOW_MS = 1_800_000_000_000


def checkpoint(
    *,
    generation: int = 7,
    minimum_epoch: int = 42,
    issued_at_ms: int = NOW_MS,
    key_id: str = "rotation-1",
    secret: bytes = SECRET,
):
    return sign_authority_epoch_checkpoint(
        provider_id="payments-postgres",
        generation=generation,
        minimum_authority_epoch=minimum_epoch,
        issued_at_ms=issued_at_ms,
        key_id=key_id,
        secret=secret,
    )


def source(state: list[tuple[str, str]], **changes):
    values = {
        "provider_id": "payments-postgres",
        "checkpoint_loader": lambda: state[0],
        "keyring": {"rotation-1": SECRET},
        "max_age_seconds": 60,
        "max_future_skew_seconds": 2,
        "clock": lambda: NOW_MS / 1_000,
    }
    values.update(changes)
    return SignedAuthorityEpochSource(**values)


def serialized(value=None) -> tuple[str, str]:
    value = value or checkpoint()
    return dump_authority_epoch_checkpoint(value), value.digest


def test_signed_checkpoint_yields_anchored_epoch_requirement() -> None:
    state = [serialized()]

    requirement = source(state).current_requirement()

    assert requirement.provider_id == "payments-postgres"
    assert requirement.minimum_authority_epoch == 42
    assert requirement.checkpoint_sha256 == checkpoint().digest
    assert load_authority_epoch_checkpoint(state[0][0]) == checkpoint()


def test_external_head_rejects_rolled_back_document() -> None:
    old = checkpoint(generation=7, minimum_epoch=42)
    new = checkpoint(generation=8, minimum_epoch=43)
    state = [(dump_authority_epoch_checkpoint(old), new.digest)]

    with pytest.raises(AuthorityEpochCheckpointError, match="anchor_mismatch"):
        source(state).current_requirement()


def test_signature_tampering_and_unknown_key_fail_closed() -> None:
    valid = checkpoint()
    tampered = replace(valid, minimum_authority_epoch=43)
    state = [(dump_authority_epoch_checkpoint(tampered), tampered.digest)]

    with pytest.raises(AuthorityEpochCheckpointError, match="signature_invalid"):
        source(state).current_requirement()

    rotated = checkpoint(key_id="rotation-2", secret=NEW_SECRET)
    state[0] = serialized(rotated)
    with pytest.raises(AuthorityEpochCheckpointError, match="key_unknown"):
        source(state).current_requirement()


def test_explicit_key_rotation_overlap_and_retirement() -> None:
    rotated = checkpoint(
        generation=8,
        minimum_epoch=43,
        key_id="rotation-2",
        secret=NEW_SECRET,
    )
    state = [serialized(rotated)]

    overlap = source(
        state,
        keyring={"rotation-1": SECRET, "rotation-2": NEW_SECRET},
    )
    assert overlap.current_requirement().minimum_authority_epoch == 43

    retired = source(state, keyring={"rotation-2": NEW_SECRET})
    assert retired.current_requirement().minimum_authority_epoch == 43


@pytest.mark.parametrize(
    ("issued_at_ms", "reason"),
    [
        (NOW_MS - 60_001, "checkpoint_stale"),
        (NOW_MS + 2_001, "checkpoint_from_future"),
    ],
)
def test_checkpoint_time_is_bounded(issued_at_ms: int, reason: str) -> None:
    state = [serialized(checkpoint(issued_at_ms=issued_at_ms))]

    with pytest.raises(AuthorityEpochCheckpointError, match=reason):
        source(state).current_requirement()


def test_generation_regression_and_equivocation_fail_closed() -> None:
    current = checkpoint(generation=8, minimum_epoch=43)
    state = [serialized(current)]
    epoch_source = source(state)
    epoch_source.current_requirement()

    state[0] = serialized(checkpoint(generation=7, minimum_epoch=42))
    with pytest.raises(AuthorityEpochCheckpointError, match="generation_regressed"):
        epoch_source.current_requirement()

    state[0] = serialized(checkpoint(generation=8, minimum_epoch=44))
    with pytest.raises(AuthorityEpochCheckpointError, match="generation_equivocated"):
        epoch_source.current_requirement()


def test_higher_generation_cannot_lower_minimum_epoch() -> None:
    current = checkpoint(generation=8, minimum_epoch=43)
    state = [serialized(current)]
    epoch_source = source(state)
    epoch_source.current_requirement()

    state[0] = serialized(checkpoint(generation=9, minimum_epoch=42))
    with pytest.raises(AuthorityEpochCheckpointError, match="epoch_regressed"):
        epoch_source.current_requirement()


def test_duplicate_unknown_and_malformed_fields_are_rejected() -> None:
    valid = checkpoint()
    document = valid.document()
    duplicated = dump_authority_epoch_checkpoint(valid).replace(
        '"generation":7',
        '"generation":7,"generation":7',
    )
    with pytest.raises(AuthorityEpochCheckpointError, match="duplicate_field"):
        load_authority_epoch_checkpoint(duplicated)

    document["unexpected"] = True
    with pytest.raises(AuthorityEpochCheckpointError, match="schema_invalid"):
        load_authority_epoch_checkpoint(json.dumps(document))

    with pytest.raises(AuthorityEpochCheckpointError, match="json_invalid"):
        load_authority_epoch_checkpoint("{")


def test_loader_failures_and_invalid_anchor_do_not_leak_diagnostics() -> None:
    def failing_loader() -> tuple[str, str]:
        raise OSError("secret control-plane endpoint")

    epoch_source = SignedAuthorityEpochSource(
        provider_id="payments-postgres",
        checkpoint_loader=failing_loader,
        keyring={"rotation-1": SECRET},
        clock=lambda: NOW_MS / 1_000,
    )
    with pytest.raises(AuthorityEpochCheckpointError, match="load_failed") as caught:
        epoch_source.current_requirement()
    assert "secret" not in str(caught.value)

    with pytest.raises(AuthorityEpochCheckpointError, match="anchor_invalid"):
        source([(dump_authority_epoch_checkpoint(checkpoint()), "bad")]).current_requirement()


@pytest.mark.parametrize(
    "changes",
    [
        {"provider_id": "unsafe provider"},
        {"generation": 0},
        {"minimum_authority_epoch": True},
        {"issued_at_ms": -1},
        {"key_id": "unsafe key"},
        {"secret": b"short"},
    ],
)
def test_signing_rejects_unsafe_checkpoint_fields(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "provider_id": "payments-postgres",
        "generation": 7,
        "minimum_authority_epoch": 42,
        "issued_at_ms": NOW_MS,
        "key_id": "rotation-1",
        "secret": SECRET,
    }
    values.update(changes)

    with pytest.raises(ValueError):
        sign_authority_epoch_checkpoint(**values)  # type: ignore[arg-type]
