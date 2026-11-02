from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
import subprocess
import sys

import pytest

import src.sqlite_binding_migration as migration_module
from src.request_identity import CanonicalRequestIdentity
from src.sqlite_binding_migration import (
    BindingMigrationError,
    migrate_terminal_bindings,
)
from src.sqlite_ledger import SQLiteExecutionLedger, inspect_terminal_bindings


def _output_sha256(database, key: str) -> str:
    with sqlite3.connect(database) as connection:
        encoded = connection.execute(
            "SELECT output_json FROM execution_ledger WHERE key = ?", (key,)
        ).fetchone()[0]
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _entry(database, key: str, tool: str, arguments: dict) -> dict[str, object]:
    identity = CanonicalRequestIdentity.from_parts(tool, arguments)
    return {
        "key": key,
        "tool": tool,
        "arguments": arguments,
        "request_sha256": identity.sha256,
        "output_sha256": _output_sha256(database, key),
    }


def _write_mapping(path, entries: list[dict[str, object]]) -> bytes:
    raw = json.dumps(
        {"schema_version": "sqlite-binding-mapping/v1", "entries": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    path.write_bytes(raw)
    return raw


def _legacy_database(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    database = tmp_path / "ledger.db"
    ledger = SQLiteExecutionLedger(database)
    ledger.record("write:legacy-a", {"saved": 7})
    ledger.record("write:legacy-b", {"saved": 8})
    return database


def test_backup_first_migration_binds_exact_requests_and_emits_reduced_receipt(
    tmp_path,
) -> None:
    database = _legacy_database(tmp_path)
    mapping = tmp_path / "mapping.json"
    backup = tmp_path / "ledger.backup.db"
    entries = [
        _entry(database, "write:legacy-a", "write", {"value": 7}),
        _entry(database, "write:legacy-b", "write", {"value": 8}),
    ]
    raw_mapping = _write_mapping(mapping, entries)

    receipt = migrate_terminal_bindings(database, mapping, backup)

    assert receipt["schema_version"] == "sqlite-binding-migration/v1"
    assert receipt["migrated_results"] == 2
    assert receipt["mapping_sha256"] == hashlib.sha256(raw_mapping).hexdigest()
    assert receipt["backup_sha256"] == hashlib.sha256(backup.read_bytes()).hexdigest()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    serialized = json.dumps(receipt, sort_keys=True)
    assert "write:legacy" not in serialized
    assert '"saved"' not in serialized
    assert inspect_terminal_bindings(database).requires_migration is False
    assert inspect_terminal_bindings(backup).legacy_unbound_results == 2

    ledger = SQLiteExecutionLedger(database)
    for entry, value in zip(entries, (7, 8), strict=True):
        assert ledger.get_for_request(entry["key"], entry["request_sha256"]) == {"saved": value}


@pytest.mark.parametrize(
    ("mutation", "code", "backup_expected"),
    [
        (lambda entries: entries[:1], "mapping_coverage_mismatch", True),
        (
            lambda entries: [*entries, {**entries[0], "key": "write:not-present"}],
            "mapping_coverage_mismatch",
            True,
        ),
        (
            lambda entries: [entries[0], entries[0]],
            "mapping_key_invalid",
            False,
        ),
        (
            lambda entries: [{**entries[0], "request_sha256": "a" * 64}, entries[1]],
            "mapping_request_digest_mismatch",
            False,
        ),
        (
            lambda entries: [{**entries[0], "output_sha256": "b" * 64}, entries[1]],
            "mapping_output_digest_mismatch",
            True,
        ),
    ],
)
def test_rejects_incomplete_extra_duplicate_or_tampered_mapping(
    tmp_path, mutation, code: str, backup_expected: bool
) -> None:
    database = _legacy_database(tmp_path)
    mapping = tmp_path / "mapping.json"
    backup = tmp_path / "ledger.backup.db"
    entries = [
        _entry(database, "write:legacy-a", "write", {"value": 7}),
        _entry(database, "write:legacy-b", "write", {"value": 8}),
    ]
    _write_mapping(mapping, mutation(entries))

    with pytest.raises(BindingMigrationError, match=code):
        migrate_terminal_bindings(database, mapping, backup)

    assert backup.exists() is backup_expected
    assert inspect_terminal_bindings(database).legacy_unbound_results == 2


def test_refuses_invalid_existing_bindings_and_active_claims(tmp_path) -> None:
    database = _legacy_database(tmp_path)
    mapping = tmp_path / "mapping.json"
    entries = [
        _entry(database, "write:legacy-a", "write", {"value": 7}),
        _entry(database, "write:legacy-b", "write", {"value": 8}),
    ]
    _write_mapping(mapping, entries)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE execution_ledger SET request_sha256 = ? WHERE key = ?",
            ("INVALID", "write:legacy-b"),
        )

    with pytest.raises(BindingMigrationError, match="invalid_existing_binding"):
        migrate_terminal_bindings(database, mapping, tmp_path / "invalid.backup.db")

    database = _legacy_database(tmp_path / "claims")
    mapping = tmp_path / "claims" / "mapping.json"
    entries = [
        _entry(database, "write:legacy-a", "write", {"value": 7}),
        _entry(database, "write:legacy-b", "write", {"value": 8}),
    ]
    _write_mapping(mapping, entries)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO execution_claims (
                key, request_sha256, fencing_token, lease_expires_at_ms,
                state, retry_count, retry_limit
            ) VALUES (?, ?, 1, 9999999999999, 'running', 0, 3)
            """,
            ("write:legacy-a", entries[0]["request_sha256"]),
        )

    with pytest.raises(BindingMigrationError, match="terminal_binding_has_active_claim"):
        migrate_terminal_bindings(database, mapping, tmp_path / "claims.backup.db")


def test_rejects_terminal_row_change_after_backup(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = _legacy_database(tmp_path)
    mapping = tmp_path / "mapping.json"
    backup = tmp_path / "ledger.backup.db"
    entries = [
        _entry(database, "write:legacy-a", "write", {"value": 7}),
        _entry(database, "write:legacy-b", "write", {"value": 8}),
    ]
    _write_mapping(mapping, entries)
    original = migration_module._create_backup

    def backup_then_race(database_path, backup_path):
        digest = original(database_path, backup_path)
        with sqlite3.connect(database_path) as connection:
            connection.execute(
                "UPDATE execution_ledger SET output_json = ? WHERE key = ?",
                ('{"saved":999}', "write:legacy-a"),
            )
        return digest

    monkeypatch.setattr(migration_module, "_create_backup", backup_then_race)

    with pytest.raises(BindingMigrationError, match="ledger_changed_after_backup"):
        migrate_terminal_bindings(database, mapping, backup)

    assert backup.exists()
    assert inspect_terminal_bindings(database).legacy_unbound_results == 2


def test_refuses_overwrite_alias_symlink_and_duplicate_json_keys(tmp_path) -> None:
    database = _legacy_database(tmp_path)
    mapping = tmp_path / "mapping.json"
    entry = _entry(database, "write:legacy-a", "write", {"value": 7})
    mapping.write_text(
        '{"schema_version":"sqlite-binding-mapping/v1",'
        '"schema_version":"sqlite-binding-mapping/v1","entries":[]}',
        encoding="utf-8",
    )
    with pytest.raises(BindingMigrationError, match="mapping_duplicate_json_key"):
        migrate_terminal_bindings(database, mapping, tmp_path / "duplicate.backup.db")

    _write_mapping(mapping, [entry])
    backup = tmp_path / "existing.db"
    backup.write_text("do not overwrite", encoding="utf-8")
    with pytest.raises(BindingMigrationError, match="backup_already_exists"):
        migrate_terminal_bindings(database, mapping, backup)
    assert backup.read_text(encoding="utf-8") == "do not overwrite"

    with pytest.raises(BindingMigrationError, match="migration_paths_must_be_distinct"):
        migrate_terminal_bindings(database, mapping, database)

    link = tmp_path / "mapping-link.json"
    link.symlink_to(mapping)
    with pytest.raises(BindingMigrationError, match="mapping_file_unavailable"):
        migrate_terminal_bindings(database, link, tmp_path / "linked.backup.db")


def test_cli_writes_private_receipt_and_sanitizes_rejection(tmp_path) -> None:
    database = _legacy_database(tmp_path)
    mapping = tmp_path / "mapping.json"
    backup = tmp_path / "ledger.backup.db"
    receipt = tmp_path / "receipt.json"
    entries = [
        _entry(database, "write:legacy-a", "write", {"value": 7}),
        _entry(database, "write:legacy-b", "write", {"value": 8}),
    ]
    _write_mapping(mapping, entries)
    command = [
        sys.executable,
        "-m",
        "tools.migrate_sqlite_bindings",
        "--database",
        str(database),
        "--mapping",
        str(mapping),
        "--backup",
        str(backup),
        "--receipt",
        str(receipt),
    ]

    completed = subprocess.run(command, check=False, capture_output=True, text=True)

    assert completed.returncode == 0, completed.stdout
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert json.loads(receipt.read_text(encoding="utf-8"))["migrated_results"] == 2
    repeated = subprocess.run(command, check=False, capture_output=True, text=True)
    assert repeated.returncode == 2
    assert "migration_output_paths_invalid" in repeated.stderr
    assert "write:legacy" not in repeated.stderr
