from __future__ import annotations

import json
import math
import ssl
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Self

from src.reconciliation_adapter import DownstreamOutcome

_MAX_REQUEST_BYTES = 4_096
_EXPECTED_REQUEST_FIELDS = {
    "fencing_token",
    "key",
    "request_sha256",
    "schema_version",
}


@dataclass(frozen=True, slots=True)
class SandboxScenario:
    """One deterministic system-of-record observation and network behavior."""

    outcome: DownstreamOutcome
    output: Mapping[str, Any] | None = None
    response_delay_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, DownstreamOutcome):
            raise TypeError("outcome must be a DownstreamOutcome")
        if self.outcome is DownstreamOutcome.COMMITTED and not isinstance(self.output, Mapping):
            raise ValueError("committed scenario requires an object output")
        if self.outcome is not DownstreamOutcome.COMMITTED and self.output is not None:
            raise ValueError("non-committed scenario cannot include output")
        if (
            isinstance(self.response_delay_seconds, bool)
            or not isinstance(self.response_delay_seconds, (int, float))
            or not math.isfinite(self.response_delay_seconds)
            or not 0 <= self.response_delay_seconds <= 30
        ):
            raise ValueError("response_delay_seconds must be finite and in [0, 30]")
        if self.output is not None:
            try:
                json.dumps(self.output, allow_nan=False)
            except (TypeError, ValueError) as exc:
                raise ValueError("output must be finite JSON") from exc


@dataclass(frozen=True, slots=True)
class CapturedRequest:
    document: dict[str, object]
    client_common_name: str | None
    received_at_ms: int


class _SandboxServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class MtlsReconciliationSandbox:
    """Disposable, loopback-only mTLS endpoint for deterministic fault injection."""

    def __init__(
        self,
        *,
        provider_id: str,
        server_cert_file: str | Path,
        server_key_file: str | Path,
        client_ca_file: str | Path,
        scenario: SandboxScenario,
    ) -> None:
        if not provider_id or len(provider_id) > 64:
            raise ValueError("provider_id must be 1-64 characters")
        self.provider_id = provider_id
        self.scenario = scenario
        self._captured: list[CapturedRequest] = []
        self._capture_lock = threading.Lock()
        self._thread: threading.Thread | None = None

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(str(server_cert_file), str(server_key_file))
        context.load_verify_locations(cafile=str(client_ca_file))

        sandbox = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                if self.path != "/v1/reconcile":
                    self.send_error(404)
                    return
                content_length = self.headers.get("Content-Length")
                if content_length is None or not content_length.isascii() or not content_length.isdigit():
                    self.send_error(400)
                    return
                body_size = int(content_length)
                if not 0 < body_size <= _MAX_REQUEST_BYTES:
                    self.send_error(413)
                    return
                body = self.rfile.read(body_size)
                if len(body) != body_size:
                    self.send_error(400)
                    return
                try:
                    document = json.loads(body.decode("utf-8", errors="strict"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self.send_error(400)
                    return
                if not isinstance(document, dict) or set(document) != _EXPECTED_REQUEST_FIELDS:
                    self.send_error(400)
                    return
                peer_certificate = self.connection.getpeercert()
                common_name = _certificate_common_name(peer_certificate)
                received_at_ms = time.time_ns() // 1_000_000
                captured = CapturedRequest(
                    document=dict(document),
                    client_common_name=common_name,
                    received_at_ms=received_at_ms,
                )
                with sandbox._capture_lock:
                    sandbox._captured.append(captured)

                time.sleep(float(sandbox.scenario.response_delay_seconds))
                response_document = {
                    **document,
                    "observed_at_ms": received_at_ms,
                    "outcome": sandbox.scenario.outcome.value,
                    "output": dict(sandbox.scenario.output) if sandbox.scenario.output is not None else None,
                    "provider_id": sandbox.provider_id,
                }
                payload = json.dumps(
                    response_document,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    # Expected when the client deadline expires after the request was observed.
                    pass

            def log_message(self, format: str, *args: object) -> None:
                return

        server = _SandboxServer(("127.0.0.1", 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self._server = server

    @property
    def endpoint(self) -> str:
        return f"https://localhost:{self._server.server_port}/v1/reconcile"

    @property
    def captured_requests(self) -> tuple[CapturedRequest, ...]:
        with self._capture_lock:
            return tuple(self._captured)

    def start(self) -> MtlsReconciliationSandbox:
        if self._thread is not None:
            raise RuntimeError("sandbox is already running")
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        self._thread = thread
        return self

    def close(self) -> None:
        if self._thread is None:
            self._server.server_close()
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("sandbox server did not stop")
        self._thread = None

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _certificate_common_name(certificate: dict[str, object]) -> str | None:
    subject = certificate.get("subject", ())
    if not isinstance(subject, tuple):
        return None
    for relative_distinguished_name in subject:
        if not isinstance(relative_distinguished_name, tuple):
            continue
        for attribute in relative_distinguished_name:
            if (
                isinstance(attribute, tuple)
                and len(attribute) == 2
                and attribute[0] == "commonName"
                and isinstance(attribute[1], str)
            ):
                return attribute[1]
    return None
