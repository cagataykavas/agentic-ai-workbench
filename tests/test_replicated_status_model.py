from __future__ import annotations

import pytest

from src.reconciliation_adapter import DownstreamOutcome, ReconciliationQuery
from tools.replicated_status_model import (
    ReplicatedStatusModel,
    ReplicationAcknowledgementUnavailable,
)

QUERY = ReconciliationQuery("write:request-7", "a" * 64, 1)
TOKEN = "b" * 64


def test_local_acknowledgement_can_be_lost_when_stale_replica_is_promoted() -> None:
    model = ReplicatedStatusModel()

    evidence = model.commit(
        QUERY,
        {"payment_id": "p-7"},
        operation_token=TOKEN,
    )
    model.promote_replica()

    assert evidence.replica_acknowledgements == 0
    assert model.observe(QUERY).outcome is DownstreamOutcome.NOT_COMMITTED


def test_replica_threshold_fails_closed_then_same_token_reconciles() -> None:
    model = ReplicatedStatusModel()

    with pytest.raises(
        ReplicationAcknowledgementUnavailable,
        match="replication_acknowledgement_unavailable",
    ):
        model.commit(
            QUERY,
            {"payment_id": "p-7"},
            operation_token=TOKEN,
            required_replica_acknowledgements=1,
        )

    assert model.replicate_all() == 1
    evidence = model.commit(
        QUERY,
        {"payment_id": "p-7"},
        operation_token=TOKEN,
        required_replica_acknowledgements=1,
    )
    model.promote_replica()

    assert evidence.sequence == 1
    assert evidence.replica_acknowledgements == 1
    assert evidence.operation_token_sha256 != TOKEN
    assert model.observe(QUERY).output == {"payment_id": "p-7"}


def test_different_operation_cannot_take_over_an_existing_claim() -> None:
    model = ReplicatedStatusModel()
    model.commit(QUERY, {"payment_id": "p-7"}, operation_token=TOKEN)

    with pytest.raises(ValueError, match="different operation"):
        model.commit(QUERY, {"payment_id": "p-8"}, operation_token="c" * 64)


@pytest.mark.parametrize("required", [True, -1, 2])
def test_replica_acknowledgement_threshold_is_bounded(required: object) -> None:
    with pytest.raises(ValueError, match="required_replica_acknowledgements"):
        ReplicatedStatusModel().commit(
            QUERY,
            {"payment_id": "p-7"},
            operation_token=TOKEN,
            required_replica_acknowledgements=required,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("token", ["short", "A" * 64, 64])
def test_operation_token_is_canonical(token: object) -> None:
    with pytest.raises(ValueError, match="operation_token"):
        ReplicatedStatusModel().commit(
            QUERY,
            {"payment_id": "p-7"},
            operation_token=token,  # type: ignore[arg-type]
        )
