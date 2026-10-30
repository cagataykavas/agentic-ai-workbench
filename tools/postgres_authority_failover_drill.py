from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from src.authority_epoch_checkpoint import (
    SignedAuthorityEpochSource,
    dump_authority_epoch_checkpoint,
    sign_authority_epoch_checkpoint,
)
from src.postgres_authority_checkpoint_store import (
    AuthorityCheckpointStoreError,
    PostgresAuthorityCheckpointStore,
)

_MAX_EVIDENCE_BYTES = 16_384
_IDENTIFIER_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_PROVIDER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_PREPARED_FIELDS = frozenset(
    {
        "checkpoint_sha256",
        "evidence_sha256",
        "generation",
        "minimum_authority_epoch",
        "phase",
        "prepared_at_ms",
        "primary_timeline",
        "provider_id",
        "replica_synchronized",
        "schema",
        "schema_version",
        "system_identifier_sha256",
    }
)
_VERIFIED_FIELDS = frozenset(
    {
        "checkpoint_sha256",
        "evidence_sha256",
        "generation",
        "minimum_authority_epoch",
        "new_timeline",
        "old_primary_isolated",
        "phase",
        "pre_failover_checkpoint_sha256",
        "pre_failover_timeline",
        "prepared_evidence_sha256",
        "provider_id",
        "recovered_checkpoint",
        "schema_version",
        "system_identifier_sha256",
        "verified_at_ms",
    }
)


class FailoverDrillError(RuntimeError):
    """A stable, non-sensitive failover drill failure."""


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(document),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FailoverDrillError("evidence_duplicate_field")
        result[key] = value
    return result


def seal_evidence(payload: Mapping[str, Any]) -> dict[str, Any]:
    if "evidence_sha256" in payload:
        raise ValueError("payload must not contain evidence_sha256")
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    return {**payload, "evidence_sha256": digest}


def _load_sealed_evidence(
    path: Path,
    *,
    fields: frozenset[str],
    error_prefix: str,
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FailoverDrillError(f"{error_prefix}_evidence_unavailable") from exc
    if not raw or len(raw) > _MAX_EVIDENCE_BYTES:
        raise FailoverDrillError(f"{error_prefix}_evidence_size_invalid")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FailoverDrillError(f"{error_prefix}_evidence_json_invalid") from exc
    if not isinstance(document, dict) or set(document) != fields:
        raise FailoverDrillError(f"{error_prefix}_evidence_schema_invalid")
    claimed = document.pop("evidence_sha256")
    if (
        not isinstance(claimed, str)
        or _SHA256_PATTERN.fullmatch(claimed) is None
        or not hmac.compare_digest(hashlib.sha256(_canonical(document)).hexdigest(), claimed)
    ):
        raise FailoverDrillError(f"{error_prefix}_evidence_digest_invalid")
    document["evidence_sha256"] = claimed
    return document


def load_prepared_evidence(path: Path) -> dict[str, Any]:
    document = _load_sealed_evidence(
        path,
        fields=_PREPARED_FIELDS,
        error_prefix="prepared",
    )
    if (
        document["schema_version"] != 1
        or document["phase"] != "prepared"
        or document["generation"] != 1
        or document["minimum_authority_epoch"] != 1
        or document["replica_synchronized"] is not True
        or type(document["primary_timeline"]) is not int
        or document["primary_timeline"] < 1
        or type(document["prepared_at_ms"]) is not int
        or not 0 < document["prepared_at_ms"] <= 9_223_372_036_854_775_807
        or not isinstance(document["provider_id"], str)
        or _PROVIDER_PATTERN.fullmatch(document["provider_id"]) is None
        or not isinstance(document["schema"], str)
        or _IDENTIFIER_PATTERN.fullmatch(document["schema"]) is None
        or not isinstance(document["checkpoint_sha256"], str)
        or _SHA256_PATTERN.fullmatch(document["checkpoint_sha256"]) is None
        or not isinstance(document["system_identifier_sha256"], str)
        or _SHA256_PATTERN.fullmatch(document["system_identifier_sha256"]) is None
    ):
        raise FailoverDrillError("prepared_evidence_fields_invalid")
    return document


def load_verified_evidence(path: Path) -> dict[str, Any]:
    document = _load_sealed_evidence(
        path,
        fields=_VERIFIED_FIELDS,
        error_prefix="verified",
    )
    if (
        document["schema_version"] != 1
        or document["phase"] != "verified"
        or document["generation"] != 2
        or document["minimum_authority_epoch"] != 2
        or document["old_primary_isolated"] is not True
        or document["recovered_checkpoint"] is not True
        or type(document["new_timeline"]) is not int
        or document["new_timeline"] < 2
        or type(document["pre_failover_timeline"]) is not int
        or document["pre_failover_timeline"] < 1
        or type(document["verified_at_ms"]) is not int
        or not 0 < document["verified_at_ms"] <= 9_223_372_036_854_775_807
        or not isinstance(document["provider_id"], str)
        or _PROVIDER_PATTERN.fullmatch(document["provider_id"]) is None
        or any(
            not isinstance(document[field], str)
            or _SHA256_PATTERN.fullmatch(document[field]) is None
            for field in (
                "checkpoint_sha256",
                "pre_failover_checkpoint_sha256",
                "prepared_evidence_sha256",
                "system_identifier_sha256",
            )
        )
    ):
        raise FailoverDrillError("verified_evidence_fields_invalid")
    return document


def audit_evidence_chain(prepared_path: Path, verified_path: Path) -> dict[str, Any]:
    prepared = load_prepared_evidence(prepared_path)
    verified = load_verified_evidence(verified_path)
    if (
        not hmac.compare_digest(verified["provider_id"], prepared["provider_id"])
        or not hmac.compare_digest(
            verified["system_identifier_sha256"],
            prepared["system_identifier_sha256"],
        )
        or not hmac.compare_digest(
            verified["pre_failover_checkpoint_sha256"],
            prepared["checkpoint_sha256"],
        )
        or not hmac.compare_digest(
            verified["prepared_evidence_sha256"],
            prepared["evidence_sha256"],
        )
        or verified["pre_failover_timeline"] != prepared["primary_timeline"]
    ):
        raise FailoverDrillError("evidence_chain_binding_invalid")
    if (
        verified["new_timeline"] <= prepared["primary_timeline"]
        or verified["verified_at_ms"] < prepared["prepared_at_ms"]
        or hmac.compare_digest(
            verified["checkpoint_sha256"],
            prepared["checkpoint_sha256"],
        )
    ):
        raise FailoverDrillError("evidence_chain_transition_invalid")
    return {
        "audit": "passed",
        "authority_epoch_transition": [
            prepared["minimum_authority_epoch"],
            verified["minimum_authority_epoch"],
        ],
        "generation_transition": [prepared["generation"], verified["generation"]],
        "prepared_evidence_sha256": prepared["evidence_sha256"],
        "provider_id": prepared["provider_id"],
        "schema_version": 1,
        "timeline_transition": [prepared["primary_timeline"], verified["new_timeline"]],
        "verified_evidence_sha256": verified["evidence_sha256"],
    }


def _write_evidence(path: Path, document: Mapping[str, Any]) -> None:
    encoded = _canonical(document) + b"\n"
    if len(encoded) > _MAX_EVIDENCE_BYTES:
        raise FailoverDrillError("evidence_size_invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_bytes(encoded)
        temporary.replace(path)
    except OSError as exc:
        raise FailoverDrillError("evidence_write_failed") from exc


def _secret() -> bytes:
    value = os.environ.get("AGENTIC_FAILOVER_SIGNING_SECRET", "")
    encoded = value.encode("utf-8")
    if not 32 <= len(encoded) <= 4_096 or any(ord(character) < 32 for character in value):
        raise FailoverDrillError("signing_secret_invalid")
    return encoded


def _psycopg():
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - exercised by the packaged extra
        raise FailoverDrillError("psycopg_unavailable") from exc
    return psycopg


def _server_state(dsn: str) -> tuple[bool, str, int]:
    psycopg = _psycopg()
    try:
        with psycopg.connect(dsn, connect_timeout=3) as connection:
            row = connection.execute(
                "SELECT pg_is_in_recovery(), system_identifier::text, "
                "(('x' || left(pg_walfile_name(pg_current_wal_lsn()), 8))::bit(32)::bigint) "
                "FROM pg_control_system()"
            ).fetchone()
    except Exception as exc:
        raise FailoverDrillError("server_state_unavailable") from exc
    if (
        row is None
        or len(row) != 3
        or type(row[0]) is not bool
        or not isinstance(row[1], str)
        or type(row[2]) is not int
        or row[2] < 1
    ):
        raise FailoverDrillError("server_state_malformed")
    return row[0], row[1], row[2]


def _wait_for_synchronous_replica(dsn: str, application_name: str, timeout_seconds: float) -> None:
    psycopg = _psycopg()
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(dsn, connect_timeout=3) as connection:
                row = connection.execute(
                    "SELECT state, sync_state FROM pg_stat_replication WHERE application_name = %s",
                    (application_name,),
                ).fetchone()
            if row is not None and tuple(row) in {("streaming", "sync"), ("streaming", "quorum")}:
                return
        except psycopg.Error:
            row = None
        time.sleep(0.25)
    raise FailoverDrillError("synchronous_replica_unavailable")


def _wait_for_replayed_checkpoint(
    store: PostgresAuthorityCheckpointStore,
    expected_digest: str,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            _, digest = store.load()
            if hmac.compare_digest(digest, expected_digest):
                return
        except AuthorityCheckpointStoreError:
            digest = None
        time.sleep(0.25)
    raise FailoverDrillError("replica_checkpoint_not_replayed")


def probe_old_primary_isolated(dsn: str, psycopg_module: Any | None = None) -> None:
    psycopg = _psycopg() if psycopg_module is None else psycopg_module
    try:
        connection = psycopg.connect(dsn, connect_timeout=2)
    except psycopg.OperationalError as exc:
        if getattr(exc, "sqlstate", None) is not None:
            raise FailoverDrillError("old_primary_probe_inconclusive") from exc
        return
    except Exception as exc:
        raise FailoverDrillError("old_primary_probe_inconclusive") from exc
    connection.close()
    raise FailoverDrillError("old_primary_still_reachable")


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    secret = _secret()
    in_recovery, system_identifier, timeline = _server_state(args.primary_dsn)
    if in_recovery:
        raise FailoverDrillError("configured_primary_is_in_recovery")
    _wait_for_synchronous_replica(
        args.primary_dsn,
        args.replica_application_name,
        args.timeout_seconds,
    )
    primary = PostgresAuthorityCheckpointStore(
        provider_id=args.provider_id,
        dsn=args.primary_dsn,
        schema=args.schema,
        timeout_seconds=3,
    )
    replica = PostgresAuthorityCheckpointStore(
        provider_id=args.provider_id,
        dsn=args.replica_dsn,
        schema=args.schema,
        timeout_seconds=3,
    )
    psycopg = _psycopg()
    try:
        with psycopg.connect(args.primary_dsn, autocommit=True, connect_timeout=3) as connection:
            connection.execute(f'CREATE SCHEMA "{args.schema}"')
    except Exception as exc:
        raise FailoverDrillError("drill_schema_creation_failed") from exc
    primary.initialize()
    checkpoint = sign_authority_epoch_checkpoint(
        provider_id=args.provider_id,
        generation=1,
        minimum_authority_epoch=1,
        issued_at_ms=time.time_ns() // 1_000_000,
        key_id="failover-drill",
        secret=secret,
    )
    checkpoint_json = dump_authority_epoch_checkpoint(checkpoint)
    if primary.compare_and_swap(checkpoint_json, expected_sha256=None) != checkpoint.digest:
        raise FailoverDrillError("initial_checkpoint_cas_failed")
    _wait_for_replayed_checkpoint(replica, checkpoint.digest, args.timeout_seconds)
    payload = {
        "checkpoint_sha256": checkpoint.digest,
        "generation": 1,
        "minimum_authority_epoch": 1,
        "phase": "prepared",
        "prepared_at_ms": time.time_ns() // 1_000_000,
        "primary_timeline": timeline,
        "provider_id": args.provider_id,
        "replica_synchronized": True,
        "schema": args.schema,
        "schema_version": 1,
        "system_identifier_sha256": hashlib.sha256(system_identifier.encode("ascii")).hexdigest(),
    }
    evidence = seal_evidence(payload)
    _write_evidence(args.evidence, evidence)
    return evidence


def verify(args: argparse.Namespace) -> dict[str, Any]:
    secret = _secret()
    prepared = load_prepared_evidence(args.prepared_evidence)
    probe_old_primary_isolated(args.old_primary_dsn)
    in_recovery, system_identifier, timeline = _server_state(args.promoted_dsn)
    if in_recovery:
        raise FailoverDrillError("promoted_node_still_in_recovery")
    system_digest = hashlib.sha256(system_identifier.encode("ascii")).hexdigest()
    if not hmac.compare_digest(system_digest, prepared["system_identifier_sha256"]):
        raise FailoverDrillError("promoted_cluster_identity_mismatch")
    if timeline <= prepared["primary_timeline"]:
        raise FailoverDrillError("promotion_timeline_not_advanced")
    store = PostgresAuthorityCheckpointStore(
        provider_id=prepared["provider_id"],
        dsn=args.promoted_dsn,
        schema=prepared["schema"],
        timeout_seconds=3,
    )
    _, recovered_digest = store.load()
    if not hmac.compare_digest(recovered_digest, prepared["checkpoint_sha256"]):
        raise FailoverDrillError("promoted_checkpoint_mismatch")
    checkpoint = sign_authority_epoch_checkpoint(
        provider_id=prepared["provider_id"],
        generation=2,
        minimum_authority_epoch=2,
        issued_at_ms=time.time_ns() // 1_000_000,
        key_id="failover-drill",
        secret=secret,
    )
    checkpoint_json = dump_authority_epoch_checkpoint(checkpoint)
    if (
        store.compare_and_swap(
            checkpoint_json,
            expected_sha256=prepared["checkpoint_sha256"],
        )
        != checkpoint.digest
    ):
        raise FailoverDrillError("promoted_checkpoint_cas_failed")
    source = SignedAuthorityEpochSource(
        provider_id=prepared["provider_id"],
        checkpoint_loader=store.load,
        keyring={"failover-drill": secret},
    )
    if source.current_requirement().minimum_authority_epoch != 2:
        raise FailoverDrillError("promoted_checkpoint_verification_failed")
    payload = {
        "checkpoint_sha256": checkpoint.digest,
        "generation": 2,
        "minimum_authority_epoch": 2,
        "new_timeline": timeline,
        "old_primary_isolated": True,
        "phase": "verified",
        "pre_failover_checkpoint_sha256": prepared["checkpoint_sha256"],
        "pre_failover_timeline": prepared["primary_timeline"],
        "prepared_evidence_sha256": prepared["evidence_sha256"],
        "provider_id": prepared["provider_id"],
        "recovered_checkpoint": True,
        "schema_version": 1,
        "system_identifier_sha256": system_digest,
        "verified_at_ms": time.time_ns() // 1_000_000,
    }
    evidence = seal_evidence(payload)
    _write_evidence(args.evidence, evidence)
    return evidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the PostgreSQL authority failover drill")
    subparsers = parser.add_subparsers(dest="phase", required=True)
    prepared = subparsers.add_parser("prepare")
    prepared.add_argument("--primary-dsn", required=True)
    prepared.add_argument("--replica-dsn", required=True)
    prepared.add_argument("--evidence", required=True, type=Path)
    prepared.add_argument("--provider-id", default="payments-postgres")
    prepared.add_argument("--schema", default="authority_failover_drill")
    prepared.add_argument("--replica-application-name", default="authority_standby")
    prepared.add_argument("--timeout-seconds", type=float, default=30)
    verified = subparsers.add_parser("verify")
    verified.add_argument("--old-primary-dsn", required=True)
    verified.add_argument("--promoted-dsn", required=True)
    verified.add_argument("--prepared-evidence", required=True, type=Path)
    verified.add_argument("--evidence", required=True, type=Path)
    audit = subparsers.add_parser(
        "audit",
        help="validate an archived prepared/verified evidence chain without database access",
    )
    audit.add_argument("--prepared-evidence", required=True, type=Path)
    audit.add_argument("--verified-evidence", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.phase == "prepare":
            evidence = prepare(args)
        elif args.phase == "verify":
            evidence = verify(args)
        else:
            evidence = audit_evidence_chain(args.prepared_evidence, args.verified_evidence)
    except FailoverDrillError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(_canonical(evidence).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
