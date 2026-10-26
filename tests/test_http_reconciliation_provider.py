from __future__ import annotations

import json
import ssl
from dataclasses import dataclass, field

import pytest

import src.http_reconciliation_provider as http_provider
from src.http_reconciliation_provider import MtlsJsonStatusProvider, build_mtls_client_context
from src.reconciliation_adapter import (
    DownstreamOutcome,
    ReconciliationQuery,
    ReconciliationUnavailableError,
)

KEY = "write:request-7"
REQUEST_SHA256 = "a" * 64
QUERY = ReconciliationQuery(KEY, REQUEST_SHA256, 1)


def response_document(**changes: object) -> dict[str, object]:
    document: dict[str, object] = {
        "fencing_token": 1,
        "key": KEY,
        "observed_at_ms": 100_000,
        "outcome": "committed",
        "output": {"payment_id": "p-7"},
        "provider_id": "payments-primary",
        "request_sha256": REQUEST_SHA256,
        "schema_version": 1,
    }
    document.update(changes)
    return document


@dataclass
class FakeResponse:
    body: bytes
    status: int = 200
    headers: dict[str, str] = field(
        default_factory=lambda: {"Content-Type": "application/json"}
    )
    read_amounts: list[int | None] = field(default_factory=list)

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)

    def read(self, amount: int | None = None) -> bytes:
        self.read_amounts.append(amount)
        return self.body if amount is None else self.body[:amount]


@dataclass
class FakeConnection:
    response: FakeResponse
    requests: list[tuple[str, str, bytes | None, dict[str, str] | None]] = field(
        default_factory=list
    )
    closed: bool = False

    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.requests.append((method, url, body, headers))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def secure_context() -> ssl.SSLContext:
    return ssl.create_default_context()


@pytest.fixture(autouse=True)
def replace_mtls_files_with_secure_test_context(monkeypatch) -> None:
    monkeypatch.setattr(
        http_provider,
        "build_mtls_client_context",
        lambda **credentials: secure_context(),
    )


def provider_for(
    response: FakeResponse,
    *,
    endpoint: str = "https://authority.example:8443/v1/reconcile",
    max_response_bytes: int = 131_072,
) -> tuple[MtlsJsonStatusProvider, FakeConnection, list[tuple[str, int, float, ssl.SSLContext]]]:
    connection = FakeConnection(response)
    calls: list[tuple[str, int, float, ssl.SSLContext]] = []

    def factory(
        host: str,
        port: int,
        timeout_seconds: float,
        context: ssl.SSLContext,
    ) -> FakeConnection:
        calls.append((host, port, timeout_seconds, context))
        return connection

    provider = MtlsJsonStatusProvider(
        provider_id="payments-primary",
        endpoint=endpoint,
        ca_file="ca.pem",
        cert_file="client.pem",
        key_file="client-key.pem",
        max_response_bytes=max_response_bytes,
        connection_factory=factory,
    )
    return provider, connection, calls


def encoded_response(**changes: object) -> FakeResponse:
    return FakeResponse(json.dumps(response_document(**changes)).encode())


def test_lookup_posts_canonical_claim_and_forwards_socket_timeout() -> None:
    provider, connection, calls = provider_for(encoded_response())

    observation = provider.lookup(QUERY, timeout_seconds=0.25)

    assert observation.outcome is DownstreamOutcome.COMMITTED
    assert observation.output == {"payment_id": "p-7"}
    assert [(host, port, timeout) for host, port, timeout, _ in calls] == [
        ("authority.example", 8443, 0.25)
    ]
    method, path, body, headers = connection.requests[0]
    assert (method, path) == ("POST", "/v1/reconcile")
    assert json.loads(body or b"") == {
        "fencing_token": 1,
        "key": KEY,
        "request_sha256": REQUEST_SHA256,
        "schema_version": 1,
    }
    assert headers == {
        "Accept": "application/json",
        "Cache-Control": "no-store",
        "Connection": "close",
        "Content-Type": "application/json",
    }
    assert connection.closed


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://authority.example/v1/reconcile",
        "https://user:password@authority.example/v1/reconcile",
        "https://authority.example/v1/reconcile?replica=true",
        "https://authority.example/v1/reconcile#fragment",
    ],
)
def test_provider_rejects_non_pinned_or_credential_bearing_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError, match="fixed HTTPS URL"):
        MtlsJsonStatusProvider(
            provider_id="payments-primary",
            endpoint=endpoint,
            ca_file="ca.pem",
            cert_file="client.pem",
            key_file="client-key.pem",
        )


def test_provider_rejects_context_without_server_authentication() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    http_provider.build_mtls_client_context = lambda **credentials: context

    with pytest.raises(ValueError, match="require certificates"):
        MtlsJsonStatusProvider(
            provider_id="payments-primary",
            endpoint="https://authority.example/v1/reconcile",
            ca_file="ca.pem",
            cert_file="client.pem",
            key_file="client-key.pem",
        )


def test_mtls_context_builder_loads_ca_and_client_identity(monkeypatch) -> None:
    class Context:
        minimum_version = None
        check_hostname = False
        verify_mode = ssl.CERT_NONE

        def __init__(self) -> None:
            self.cert_chain: tuple[str, str] | None = None

        def load_cert_chain(self, *, certfile: str, keyfile: str) -> None:
            self.cert_chain = (certfile, keyfile)

    context = Context()
    calls: list[tuple[ssl.Purpose, str]] = []

    def create_default_context(purpose: ssl.Purpose, *, cafile: str) -> Context:
        calls.append((purpose, cafile))
        return context

    monkeypatch.setattr(http_provider.ssl, "create_default_context", create_default_context)

    built = build_mtls_client_context(
        ca_file="ca.pem",
        cert_file="client.pem",
        key_file="client-key.pem",
    )

    assert built is context
    assert calls == [(ssl.Purpose.SERVER_AUTH, "ca.pem")]
    assert context.cert_chain == ("client.pem", "client-key.pem")
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert context.check_hostname
    assert context.verify_mode is ssl.CERT_REQUIRED


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (FakeResponse(b"{}", status=503), "non-200"),
        (FakeResponse(b"{}", headers={"Content-Type": "text/plain"}), "application/json"),
        (
            FakeResponse(b"{}", headers={"Content-Type": "application/json; charset=latin-1"}),
            "UTF-8 application/json",
        ),
        (
            FakeResponse(
                b"{}",
                headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            ),
            "encoding",
        ),
        (FakeResponse(b"not-json"), "UTF-8 JSON"),
        (
            FakeResponse(
                b'{"schema_version":1,"schema_version":1}',
            ),
            "duplicate",
        ),
        (encoded_response(schema_version=2), "schema version"),
        (encoded_response(outcome="probably_committed"), "outcome"),
        (encoded_response(fencing_token=True), "fencing token"),
        (encoded_response(output=["not", "an", "object"]), "output"),
    ],
)
def test_malformed_or_ambiguous_response_fails_closed(
    response: FakeResponse,
    message: str,
) -> None:
    provider, connection, _ = provider_for(response)

    with pytest.raises(ReconciliationUnavailableError, match=message):
        provider.lookup(QUERY, timeout_seconds=0.25)

    assert connection.closed


def test_body_larger_than_policy_limit_is_read_once_and_rejected() -> None:
    response = FakeResponse(b"x" * 1_025)
    provider, connection, _ = provider_for(response, max_response_bytes=1_024)

    with pytest.raises(ReconciliationUnavailableError, match="byte limit"):
        provider.lookup(QUERY, timeout_seconds=0.25)

    assert response.read_amounts == [1_025]
    assert connection.closed


def test_declared_oversized_body_is_rejected_without_reading() -> None:
    response = FakeResponse(
        b"ignored",
        headers={"Content-Type": "application/json", "Content-Length": "1025"},
    )
    provider, connection, _ = provider_for(response, max_response_bytes=1_024)

    with pytest.raises(ReconciliationUnavailableError, match="byte limit"):
        provider.lookup(QUERY, timeout_seconds=0.25)

    assert response.read_amounts == []
    assert connection.closed


def test_transport_failure_is_normalized_without_leaking_diagnostics() -> None:
    def factory(
        host: str,
        port: int,
        timeout_seconds: float,
        ssl_context: ssl.SSLContext,
    ) -> FakeConnection:
        raise TimeoutError("internal address and credential label")

    provider = MtlsJsonStatusProvider(
        provider_id="payments-primary",
        endpoint="https://authority.example/v1/reconcile",
        ca_file="ca.pem",
        cert_file="client.pem",
        key_file="client-key.pem",
        connection_factory=factory,
    )

    with pytest.raises(ReconciliationUnavailableError, match="HTTPS transport failed") as caught:
        provider.lookup(QUERY, timeout_seconds=0.25)

    assert "internal address" not in str(caught.value)
