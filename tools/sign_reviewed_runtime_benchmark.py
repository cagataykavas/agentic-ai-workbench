#!/usr/bin/env python3
"""Reconstruct and sign the reviewed runtime benchmark in protected CI."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from src.reviewed_runtime_benchmark import sign_reviewed_runtime_benchmark
from src.runtime_eval_manifest import dump_runtime_benchmark_manifest


_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}")


def _write_private_new(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ValueError("manifest output must be a new private file") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reconstruct, gate, and sign the reviewed governed-runtime benchmark."
    )
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--key-id", default="runtime-benchmark-signing-v1")
    parser.add_argument(
        "--secret-environment",
        default="RUNTIME_BENCHMARK_SIGNING_SECRET",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if _ENVIRONMENT_NAME.fullmatch(args.secret_environment) is None:
            raise ValueError("secret environment variable name is invalid")
        secret_value = os.environ.get(args.secret_environment)
        if secret_value is None:
            raise ValueError("runtime benchmark signing secret is unavailable")
        secret = secret_value.encode("utf-8")
        report, manifest = sign_reviewed_runtime_benchmark(
            source_revision=args.source_revision,
            key_id=args.key_id,
            secret=secret,
        )
        _write_private_new(args.output, dump_runtime_benchmark_manifest(manifest))
        receipt = {
            "manifest_sha256": manifest.sha256,
            "planned_actions": report.metrics.planned_actions,
            "scenario_suite_sha256": manifest.scenario_suite_sha256,
            "status": "pass",
            "trace_count": report.metrics.trace_count,
        }
        print(json.dumps(receipt, allow_nan=False, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        print(f"reviewed runtime benchmark rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
