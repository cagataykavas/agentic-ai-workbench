from __future__ import annotations

import http.client
import json
import math
import re
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

from src.reconciliation_adapter import (
    DownstreamObservation,
    DownstreamOutcome,
    ReconciliationQuery,
    ReconciliationUnavailableError,
)

_PROVIDER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_MAX_ENDPOINT_BYTES = 2_048
_DEFAULT_MAX_RESPONSE_BYTES = 131_072
_MAX_RESPONSE_BYTES = 1_048_576
_EXPECTED_RESPONSE_FIELDS = {
    "fencing_token",
    "key",
    "observed_at_ms",
    "outcome",
    "output",
    "provider_id",
    "request_sha256",
    "schema_version",
}


class _HttpResponse(Protocol):
    status: int

    def getheader(self, name: str, default: str | None = None) -> str | None: ...

    def read(self, amount: int | None = None) -> bytes: ...


class _HttpsConnection(Protocol):
    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None: ...

    def getresponse(self) -> _HttpResponse: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[str, int, float, ssl.SSLContext], _HttpsConnection]


def build_mtls_client_context(
    *,
    ca_file: str | Path,
    cert_file: str | Path,
    key_file: str | Path,
) -> ssl.SSLContext:
    """Build a hostname-verifying TLS client context with a client certificate."""

    paths = (str(ca_file), str(cert_file), str(key_file))
    if any(not path or "\x00" in path for path in paths):
        raise ValueError("mTLS credential paths must be non-empty and contain no NUL bytes")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=paths[0])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=paths[1], keyfile=paths[2])
    return context


def _default_connection_factory(
    host: str,
    port: int,
    timeout_seconds: float,
    context: ssl.SSLContext,
) -> _HttpsConnection:
    return http.client.HTTPSConnection(
        host=host,
        port=port,
        timeout=timeout_seconds,
        context=context,
    )


def _parse_endpoint(endpoint: str) -> SplitResult:
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError("endpoint must be a non-empty HTTPS URL")
    if len(endpoint.encode("utf-8")) > _MAX_ENDPOINT_BYTES or any(ord(char) < 32 for char in endpoint):
        raise ValueError("endpoint must be at most 2048 UTF-8 bytes without control characters")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint is not a valid HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise ValueError("endpoint must be a fixed HTTPS URL without credentials, query, or fragment")
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("endpoint port must be in [1, 65535]")
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ReconciliationUnavailableError("provider response contains duplicate fields")
        document[key] = value
    return document


class MtlsJsonStatusProvider:
    """Read authoritative claim state from one pinned HTTPS JSON endpoint."""

    def __init__(
        self,
        *,
        provider_id: str,
        endpoint: str,
        ca_file: str | Path,
        cert_file: str | Path,
        key_file: str | Path,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        connection_factory: ConnectionFactory = _default_connection_factory,
    ) -> None:
        if not isinstance(provider_id, str) or not _PROVIDER_ID_PATTERN.fullmatch(provider_id):
            raise ValueError("provider_id must be 1-64 safe characters")
        if (
            type(max_response_bytes) is not int
            or not 1_024 <= max_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise ValueError("max_response_bytes must be an integer in [1024, 1048576]")
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        parsed = _parse_endpoint(endpoint)
        ssl_context = build_mtls_client_context(
            ca_file=ca_file,
            cert_file=cert_file,
            key_file=key_file,
        )
        if not isinstance(ssl_context, ssl.SSLContext):
            raise TypeError("mTLS context builder must return an SSLContext")
        if ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
            raise ValueError("mTLS context must require certificates and verify hostnames")
        self.provider_id = provider_id
        self._host = parsed.hostname
        self._port = parsed.port or 443
        self._path = parsed.path
        self._ssl_context = ssl_context
        self._max_response_bytes = max_response_bytes
        self._connection_factory = connection_factory

    @staticmethod
    def _request_document(query: ReconciliationQuery) -> dict[str, object]:
        if not isinstance(query, ReconciliationQuery):
            raise TypeError("query must be a ReconciliationQuery")
        return {
            "fencing_token": query.fencing_token,
            "key": query.key,
            "request_sha256": query.request_sha256,
            "schema_version": 1,
        }

    def _read_response(self, response: _HttpResponse) -> bytes:
        if response.status != 200:
            raise ReconciliationUnavailableError("provider returned a non-200 status")
        content_type = response.getheader("Content-Type", "") or ""
        content_type_parts = [part.strip().lower() for part in content_type.split(";")]
        if content_type_parts[0] != "application/json" or any(
            part not in {"charset=utf-8", 'charset="utf-8"'} for part in content_type_parts[1:]
        ):
            raise ReconciliationUnavailableError("provider response is not UTF-8 application/json")
        content_encoding = (response.getheader("Content-Encoding", "identity") or "identity").lower()
        if content_encoding != "identity":
            raise ReconciliationUnavailableError("provider response encoding is unsupported")
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            if not content_length.isascii() or not content_length.isdigit():
                raise ReconciliationUnavailableError("provider content length is malformed")
            if int(content_length) > self._max_response_bytes:
                raise ReconciliationUnavailableError("provider response exceeds the byte limit")
        payload = response.read(self._max_response_bytes + 1)
        if not isinstance(payload, bytes):
            raise ReconciliationUnavailableError("provider response body is malformed")
        if len(payload) > self._max_response_bytes:
            raise ReconciliationUnavailableError("provider response exceeds the byte limit")
        return payload

    def _parse_observation(self, payload: bytes) -> DownstreamObservation:
        try:
            document = json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ReconciliationUnavailableError("provider response contains non-finite JSON")
                ),
            )
        except ReconciliationUnavailableError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReconciliationUnavailableError("provider response is not valid UTF-8 JSON") from exc
        if not isinstance(document, dict) or set(document) != _EXPECTED_RESPONSE_FIELDS:
            raise ReconciliationUnavailableError("provider response schema is unsupported")
        if type(document["schema_version"]) is not int or document["schema_version"] != 1:
            raise ReconciliationUnavailableError("provider response schema version is unsupported")
        provider_id = document["provider_id"]
        key = document["key"]
        request_sha256 = document["request_sha256"]
        fencing_token = document["fencing_token"]
        observed_at_ms = document["observed_at_ms"]
        output = document["output"]
        if not isinstance(provider_id, str) or not _PROVIDER_ID_PATTERN.fullmatch(provider_id):
            raise ReconciliationUnavailableError("provider response identity is malformed")
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 512:
            raise ReconciliationUnavailableError("provider response key is malformed")
        if not isinstance(request_sha256, str) or not _SHA256_PATTERN.fullmatch(request_sha256):
            raise ReconciliationUnavailableError("provider response request digest is malformed")
        if type(fencing_token) is not int or not 0 < fencing_token <= 9_223_372_036_854_775_807:
            raise ReconciliationUnavailableError("provider response fencing token is malformed")
        if type(observed_at_ms) is not int or observed_at_ms < 0:
            raise ReconciliationUnavailableError("provider response observation time is malformed")
        if output is not None and not isinstance(output, dict):
            raise ReconciliationUnavailableError("provider response output is malformed")
        try:
            outcome = DownstreamOutcome(document["outcome"])
        except (TypeError, ValueError) as exc:
            raise ReconciliationUnavailableError("provider response outcome is unsupported") from exc
        return DownstreamObservation(
            provider_id=provider_id,
            outcome=outcome,
            key=key,
            request_sha256=request_sha256,
            fencing_token=fencing_token,
            observed_at_ms=observed_at_ms,
            output=output,
        )

    def lookup(
        self,
        query: ReconciliationQuery,
        *,
        timeout_seconds: float,
    ) -> DownstreamObservation:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 30
        ):
            raise ValueError("timeout_seconds must be finite and in (0, 30]")
        document = self._request_document(query)
        body = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        connection: _HttpsConnection | None = None
        try:
            connection = self._connection_factory(
                self._host,
                self._port,
                float(timeout_seconds),
                self._ssl_context,
            )
            connection.request(
                "POST",
                self._path,
                body=body,
                headers={
                    "Accept": "application/json",
                    "Cache-Control": "no-store",
                    "Connection": "close",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            return self._parse_observation(self._read_response(response))
        except ReconciliationUnavailableError:
            raise
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
            raise ReconciliationUnavailableError("provider HTTPS transport failed") from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except (OSError, http.client.HTTPException):
                    pass
