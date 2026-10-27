from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from src.http_reconciliation_provider import MtlsJsonStatusProvider
from src.reconciliation import ReceiptAuthenticator
from src.reconciliation_adapter import (
    AuthoritativeReconciliationCoordinator,
    DownstreamOutcome,
    NegativeObservationPolicy,
    ReconciliationQuery,
    ReconciliationUnavailableError,
)
from tools.mtls_reconciliation_sandbox import MtlsReconciliationSandbox, SandboxScenario
from tools.replicated_status_model import (
    ReplicatedStatusModel,
    ReplicationAcknowledgementUnavailable,
)

KEY = "write:request-7"
REQUEST_SHA256 = "a" * 64
QUERY = ReconciliationQuery(KEY, REQUEST_SHA256, 1)


@pytest.fixture(scope="module")
def certificates(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    if shutil.which("openssl") is None:
        pytest.fail("OpenSSL CLI is required for the live mTLS integration contract")
    directory = tmp_path_factory.mktemp("mtls-certificates")
    _run_openssl(
        directory,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-days",
        "1",
        "-subj",
        "/CN=Agentic Workbench Test CA",
        "-keyout",
        "ca-key.pem",
        "-out",
        "ca.pem",
    )
    _issue_certificate(directory, "server", "localhost", "serverAuth", "subjectAltName=DNS:localhost")
    _issue_certificate(directory, "client", "agent-reconciler", "clientAuth")
    return {
        "ca": directory / "ca.pem",
        "server_cert": directory / "server.pem",
        "server_key": directory / "server-key.pem",
        "client_cert": directory / "client.pem",
        "client_key": directory / "client-key.pem",
    }


def _run_openssl(directory: Path, *arguments: str) -> None:
    subprocess.run(
        ["openssl", *arguments],
        cwd=directory,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    )


def _issue_certificate(
    directory: Path,
    name: str,
    common_name: str,
    extended_key_usage: str,
    *extra_extensions: str,
) -> None:
    _run_openssl(
        directory,
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-subj",
        f"/CN={common_name}",
        "-keyout",
        f"{name}-key.pem",
        "-out",
        f"{name}.csr",
    )
    extension_file = directory / f"{name}.ext"
    extension_file.write_text(
        "\n".join([f"extendedKeyUsage={extended_key_usage}", *extra_extensions, ""]),
        encoding="utf-8",
    )
    _run_openssl(
        directory,
        "x509",
        "-req",
        "-sha256",
        "-days",
        "1",
        "-in",
        f"{name}.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca-key.pem",
        "-CAcreateserial",
        "-extfile",
        f"{name}.ext",
        "-out",
        f"{name}.pem",
    )


def _provider(certificates: dict[str, Path], endpoint: str) -> MtlsJsonStatusProvider:
    return MtlsJsonStatusProvider(
        provider_id="payments-primary",
        endpoint=endpoint,
        ca_file=certificates["ca"],
        cert_file=certificates["client_cert"],
        key_file=certificates["client_key"],
    )


def test_live_mutual_tls_handshake_authenticates_client_and_echoes_claim(
    certificates: dict[str, Path],
) -> None:
    scenario = SandboxScenario(
        outcome=DownstreamOutcome.COMMITTED,
        output={"payment_id": "p-7"},
    )
    with MtlsReconciliationSandbox(
        provider_id="payments-primary",
        server_cert_file=certificates["server_cert"],
        server_key_file=certificates["server_key"],
        client_ca_file=certificates["ca"],
        scenario=scenario,
    ) as sandbox:
        observation = _provider(certificates, sandbox.endpoint).lookup(QUERY, timeout_seconds=1)

        assert observation.outcome is DownstreamOutcome.COMMITTED
        assert observation.output == {"payment_id": "p-7"}
        assert len(sandbox.captured_requests) == 1
        captured = sandbox.captured_requests[0]
        assert captured.client_common_name == "agent-reconciler"
        assert captured.document == {
            "fencing_token": 1,
            "key": KEY,
            "request_sha256": REQUEST_SHA256,
            "schema_version": 1,
        }


def test_server_rejects_certificate_without_client_auth_usage(
    certificates: dict[str, Path],
) -> None:
    scenario = SandboxScenario(
        outcome=DownstreamOutcome.COMMITTED,
        output={"payment_id": "p-7"},
    )
    with MtlsReconciliationSandbox(
        provider_id="payments-primary",
        server_cert_file=certificates["server_cert"],
        server_key_file=certificates["server_key"],
        client_ca_file=certificates["ca"],
        scenario=scenario,
    ) as sandbox:
        provider = MtlsJsonStatusProvider(
            provider_id="payments-primary",
            endpoint=sandbox.endpoint,
            ca_file=certificates["ca"],
            cert_file=certificates["server_cert"],
            key_file=certificates["server_key"],
        )

        with pytest.raises(ReconciliationUnavailableError, match="HTTPS transport failed"):
            provider.lookup(QUERY, timeout_seconds=1)

        assert sandbox.captured_requests == ()


def test_timeout_after_request_is_observed_remains_fail_closed(
    certificates: dict[str, Path],
) -> None:
    scenario = SandboxScenario(
        outcome=DownstreamOutcome.COMMITTED,
        output={"payment_id": "p-7"},
        response_delay_seconds=0.2,
    )
    with MtlsReconciliationSandbox(
        provider_id="payments-primary",
        server_cert_file=certificates["server_cert"],
        server_key_file=certificates["server_key"],
        client_ca_file=certificates["ca"],
        scenario=scenario,
    ) as sandbox:
        provider = _provider(certificates, sandbox.endpoint)

        with pytest.raises(ReconciliationUnavailableError, match="HTTPS transport failed"):
            provider.lookup(QUERY, timeout_seconds=0.05)

        deadline = time.monotonic() + 1
        while not sandbox.captured_requests and time.monotonic() < deadline:
            time.sleep(0.005)
        assert len(sandbox.captured_requests) == 1
        assert sandbox.captured_requests[0].document["key"] == KEY


def test_live_lookup_exposes_primary_only_commit_loss_after_failover(
    certificates: dict[str, Path],
) -> None:
    model = ReplicatedStatusModel()
    evidence = model.commit(
        QUERY,
        {"payment_id": "p-7"},
        operation_token="b" * 64,
    )
    model.promote_replica()

    with MtlsReconciliationSandbox(
        provider_id="payments-primary",
        server_cert_file=certificates["server_cert"],
        server_key_file=certificates["server_key"],
        client_ca_file=certificates["ca"],
        status_model=model,
    ) as sandbox:
        observation = _provider(certificates, sandbox.endpoint).lookup(QUERY, timeout_seconds=1)

    assert evidence.replica_acknowledgements == 0
    assert observation.outcome is DownstreamOutcome.NOT_COMMITTED
    assert observation.output is None
    assert observation.negative_proof is not None
    assert observation.negative_proof.authority_epoch == 2
    assert observation.negative_proof.durable_sequence == 0
    assert observation.negative_proof.replica_acknowledgements == 0


def test_live_negative_observation_below_durable_sequence_fails_closed(
    certificates: dict[str, Path],
) -> None:
    model = ReplicatedStatusModel()
    model.commit(
        QUERY,
        {"payment_id": "p-7"},
        operation_token="b" * 64,
    )
    model.promote_replica()

    with MtlsReconciliationSandbox(
        provider_id="payments-primary",
        server_cert_file=certificates["server_cert"],
        server_key_file=certificates["server_key"],
        client_ca_file=certificates["ca"],
        status_model=model,
    ) as sandbox:
        coordinator = AuthoritativeReconciliationCoordinator(
            _provider(certificates, sandbox.endpoint),
            ReceiptAuthenticator(
                {"current": b"a" * 32},
                signing_key_id="current",
                max_age_seconds=30,
            ),
            negative_observation_policy=NegativeObservationPolicy(
                minimum_authority_epoch=2,
                minimum_durable_sequence=1,
            ),
            lookup_timeout_seconds=1,
        )

        with pytest.raises(ReconciliationUnavailableError, match="does not satisfy retry policy"):
            coordinator.reconcile(QUERY, retry_lease_seconds=1)


def test_live_lookup_preserves_replica_acknowledged_commit_after_failover(
    certificates: dict[str, Path],
) -> None:
    model = ReplicatedStatusModel()
    with pytest.raises(ReplicationAcknowledgementUnavailable):
        model.commit(
            QUERY,
            {"payment_id": "p-7"},
            operation_token="b" * 64,
            required_replica_acknowledgements=1,
        )
    model.replicate_all()
    evidence = model.commit(
        QUERY,
        {"payment_id": "p-7"},
        operation_token="b" * 64,
        required_replica_acknowledgements=1,
    )
    model.promote_replica()

    with MtlsReconciliationSandbox(
        provider_id="payments-primary",
        server_cert_file=certificates["server_cert"],
        server_key_file=certificates["server_key"],
        client_ca_file=certificates["ca"],
        status_model=model,
    ) as sandbox:
        observation = _provider(certificates, sandbox.endpoint).lookup(QUERY, timeout_seconds=1)

    assert evidence.replica_acknowledgements == 1
    assert observation.outcome is DownstreamOutcome.COMMITTED
    assert observation.output == {"payment_id": "p-7"}
    assert observation.negative_proof is None
