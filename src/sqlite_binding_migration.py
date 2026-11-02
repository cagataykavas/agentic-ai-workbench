"""Backup-first migration for legacy SQLite terminal request bindings."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from src.request_identity import CanonicalRequestError, CanonicalRequestIdentity
from src.sqlite_ledger import LedgerCorruptionError, SQLiteExecutionLedger

MAPPING_SCHEMA = "sqlite-binding-mapping/v1"
RECEIPT_SCHEMA = "sqlite-binding-migration/v1"
MAX_MAPPING_BYTES = 1_048_576
MAX_MAPPING_ENTRIES = 1_000
_SHA256 = re.compile(r"[0-9a-f]{64}")


class BindingMigrationError(RuntimeError):
    """A legacy binding migration could not be completed safely."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _ReviewedBinding:
    key: str
    request_sha256: str
    output_sha256: str


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise BindingMigrationError("mapping_duplicate_json_key")
        value[key] = item
    return value


def _read_private_file(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= maximum:
            raise BindingMigrationError("mapping_file_invalid")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) != metadata.st_size:
            raise BindingMigrationError("mapping_file_changed")
        return raw
    except OSError as exc:
        raise BindingMigrationError("mapping_file_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_mapping(raw: bytes) -> list[_ReviewedBinding]:
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BindingMigrationError("mapping_json_invalid") from exc
    if not isinstance(document, dict) or set(document) != {"schema_version", "entries"}:
        raise BindingMigrationError("mapping_schema_invalid")
    if document["schema_version"] != MAPPING_SCHEMA:
        raise BindingMigrationError("mapping_schema_unsupported")
    entries = document["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_MAPPING_ENTRIES:
        raise BindingMigrationError("mapping_entries_invalid")

    reviewed: list[_ReviewedBinding] = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != {
            "key",
            "tool",
            "arguments",
            "request_sha256",
            "output_sha256",
        }:
            raise BindingMigrationError("mapping_entry_schema_invalid")
        key = item["key"]
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 512 or key in seen:
            raise BindingMigrationError("mapping_key_invalid")
        request_sha256 = item["request_sha256"]
        output_sha256 = item["output_sha256"]
        if (
            not isinstance(request_sha256, str)
            or _SHA256.fullmatch(request_sha256) is None
            or not isinstance(output_sha256, str)
            or _SHA256.fullmatch(output_sha256) is None
        ):
            raise BindingMigrationError("mapping_digest_invalid")
        try:
            identity = CanonicalRequestIdentity.from_parts(
                item["tool"],
                item["arguments"],
            )
        except CanonicalRequestError as exc:
            raise BindingMigrationError("mapping_request_invalid") from exc
        if identity.sha256 != request_sha256:
            raise BindingMigrationError("mapping_request_digest_mismatch")
        seen.add(key)
        reviewed.append(
            _ReviewedBinding(
                key=key,
                request_sha256=request_sha256,
                output_sha256=output_sha256,
            )
        )
    return reviewed


def _database_path(database: Path) -> Path:
    if database.is_symlink() or not database.is_file():
        raise BindingMigrationError("ledger_unavailable")
    return database.resolve()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _create_backup(database: Path, backup: Path) -> str:
    if backup.exists() or backup.is_symlink():
        raise BindingMigrationError("backup_already_exists")
    backup.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=backup.parent,
        prefix=f".{backup.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with (
            sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as source,
            sqlite3.connect(temporary) as destination,
        ):
            source.backup(destination)
        os.chmod(temporary, 0o600)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        temporary.replace(backup)
        directory = os.open(backup.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return _sha256_file(backup)
    except (OSError, sqlite3.Error) as exc:
        temporary.unlink(missing_ok=True)
        raise BindingMigrationError("backup_failed") from exc


def _terminal_rows(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    try:
        columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(execution_ledger)")}
        if not {"key", "request_sha256", "output_json"}.issubset(columns):
            raise BindingMigrationError("execution_ledger_schema_unsupported")
        invalid = connection.execute(
            """
            SELECT COUNT(*) FROM execution_ledger
            WHERE request_sha256 IS NOT NULL AND (
                typeof(request_sha256) != 'text'
                OR length(request_sha256) != 64
                OR request_sha256 GLOB '*[^0-9a-f]*'
            )
            """
        ).fetchone()[0]
        if invalid:
            raise BindingMigrationError("invalid_existing_binding")
        return list(
            connection.execute(
                """
                SELECT key, output_json FROM execution_ledger
                WHERE request_sha256 IS NULL ORDER BY key
                """
            )
        )
    except sqlite3.Error as exc:
        raise BindingMigrationError("ledger_inspection_failed") from exc


def _ledger_commitment(connection: sqlite3.Connection) -> str:
    """Commit to every terminal row without serializing it outside the process."""
    digest = hashlib.sha256(b"sqlite-terminal-ledger/v1\0")
    try:
        rows = connection.execute(
            """
            SELECT key, request_sha256, output_json
            FROM execution_ledger ORDER BY key
            """
        )
        for row in rows:
            values = (row["key"], row["request_sha256"], row["output_json"])
            for value in values:
                if value is None:
                    encoded = b""
                    marker = b"n"
                elif isinstance(value, str):
                    encoded = value.encode("utf-8")
                    marker = b"s"
                else:
                    raise BindingMigrationError("ledger_row_invalid")
                digest.update(marker)
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
        return digest.hexdigest()
    except UnicodeEncodeError as exc:
        raise BindingMigrationError("ledger_row_invalid") from exc
    except sqlite3.Error as exc:
        raise BindingMigrationError("ledger_inspection_failed") from exc


def _binding_commitment(bindings: list[_ReviewedBinding]) -> str:
    reduced = [
        {
            "key_sha256": hashlib.sha256(item.key.encode("utf-8")).hexdigest(),
            "request_sha256": item.request_sha256,
            "output_sha256": item.output_sha256,
        }
        for item in sorted(bindings, key=lambda value: value.key)
    ]
    payload = json.dumps(reduced, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def migrate_terminal_bindings(
    database: str | os.PathLike[str],
    mapping: str | os.PathLike[str],
    backup: str | os.PathLike[str],
) -> dict[str, int | str]:
    """Back up and bind every legacy terminal row to one reviewed request identity."""

    database_path = _database_path(Path(database))
    mapping_path = Path(mapping)
    backup_path = Path(backup)
    resolved = {database_path, mapping_path.resolve(), backup_path.resolve()}
    if len(resolved) != 3:
        raise BindingMigrationError("migration_paths_must_be_distinct")
    raw_mapping = _read_private_file(mapping_path, maximum=MAX_MAPPING_BYTES)
    reviewed = _parse_mapping(raw_mapping)
    backup_sha256 = _create_backup(database_path, backup_path)
    try:
        with sqlite3.connect(f"{backup_path.resolve().as_uri()}?mode=ro", uri=True) as backup_connection:
            backup_connection.row_factory = sqlite3.Row
            backup_ledger_sha256 = _ledger_commitment(backup_connection)
    except (OSError, sqlite3.Error) as exc:
        raise BindingMigrationError("backup_verification_failed") from exc

    try:
        with sqlite3.connect(database_path, isolation_level=None) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("BEGIN IMMEDIATE")
            try:
                if _ledger_commitment(connection) != backup_ledger_sha256:
                    raise BindingMigrationError("ledger_changed_after_backup")
                rows = _terminal_rows(connection)
                by_key = {item.key: item for item in reviewed}
                if not rows:
                    raise BindingMigrationError("migration_not_required")
                if {str(row["key"]) for row in rows} != set(by_key):
                    raise BindingMigrationError("mapping_coverage_mismatch")
                for row in rows:
                    key = str(row["key"])
                    item = by_key[key]
                    encoded_output = row["output_json"]
                    if not isinstance(encoded_output, str):
                        raise BindingMigrationError("ledger_output_invalid")
                    try:
                        SQLiteExecutionLedger._decode(encoded_output)
                    except LedgerCorruptionError as exc:
                        raise BindingMigrationError("ledger_output_invalid") from exc
                    actual_output_sha256 = hashlib.sha256(encoded_output.encode("utf-8")).hexdigest()
                    if actual_output_sha256 != item.output_sha256:
                        raise BindingMigrationError("mapping_output_digest_mismatch")
                    active_claim = connection.execute(
                        "SELECT 1 FROM execution_claims WHERE key = ?",
                        (key,),
                    ).fetchone()
                    if active_claim is not None:
                        raise BindingMigrationError("terminal_binding_has_active_claim")
                    changed = connection.execute(
                        """
                        UPDATE execution_ledger SET request_sha256 = ?
                        WHERE key = ? AND request_sha256 IS NULL
                        """,
                        (item.request_sha256, key),
                    ).rowcount
                    if changed != 1:
                        raise BindingMigrationError("terminal_binding_changed")
                connection.commit()
            except Exception:
                connection.rollback()
                raise
    except BindingMigrationError:
        raise
    except sqlite3.Error as exc:
        raise BindingMigrationError("migration_failed") from exc

    return {
        "schema_version": RECEIPT_SCHEMA,
        "migrated_results": len(reviewed),
        "mapping_sha256": hashlib.sha256(raw_mapping).hexdigest(),
        "backup_sha256": backup_sha256,
        "bindings_sha256": _binding_commitment(reviewed),
    }
