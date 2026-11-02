#!/usr/bin/env python3
"""Migrate legacy SQLite request bindings from a reviewed private mapping."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from src.sqlite_binding_migration import BindingMigrationError, migrate_terminal_bindings


def _write_receipt(path: Path, receipt: dict[str, int | str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Back up and bind legacy SQLite terminal results to reviewed requests."
    )
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()

    try:
        resolved = {
            args.database.resolve(),
            args.mapping.resolve(),
            args.backup.resolve(),
            args.receipt.resolve(),
        }
        if len(resolved) != 4 or args.receipt.exists():
            raise BindingMigrationError("migration_output_paths_invalid")
        receipt = migrate_terminal_bindings(args.database, args.mapping, args.backup)
        _write_receipt(args.receipt, receipt)
        return 0
    except (BindingMigrationError, OSError) as exc:
        code = exc.code if isinstance(exc, BindingMigrationError) else "receipt_write_failed"
        print(f"SQLite binding migration rejected: {code}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
