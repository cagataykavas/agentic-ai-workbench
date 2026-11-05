#!/usr/bin/env python3
"""Verify independent provenance for one runtime benchmark manifest."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from src.runtime_eval_attestation import (
    RuntimeBenchmarkAttestationPolicy,
    verify_runtime_benchmark_attestation,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify a runtime benchmark manifest's GitHub artifact attestation."
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--signer-workflow", required=True)
    parser.add_argument("--signer-digest", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--trusted-root", type=Path)
    parser.add_argument("--repository-id")
    parser.add_argument("--gh-executable", default="gh")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--output", type=Path)
    return parser


def write_receipt(receipt: dict[str, Any], output: Path) -> None:
    """Atomically persist a private deterministic verification receipt."""
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, allow_nan=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = {args.manifest.resolve()}
        for optional in (args.bundle, args.trusted_root):
            if optional is not None:
                inputs.add(optional.resolve())
        if args.output is not None and args.output.resolve() in inputs:
            raise ValueError("output must not replace an attestation input")
        policy = RuntimeBenchmarkAttestationPolicy(
            repository=args.repository,
            signer_workflow=args.signer_workflow,
            signer_digest=args.signer_digest,
            source_ref=args.source_ref,
        )
        receipt = verify_runtime_benchmark_attestation(
            args.manifest,
            expected_manifest_sha256=args.expected_manifest_sha256,
            policy=policy,
            bundle=args.bundle,
            trusted_root=args.trusted_root,
            repository_id=args.repository_id,
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
        )
        if args.output is None:
            print(json.dumps(receipt, allow_nan=False, indent=2, sort_keys=True))
        else:
            write_receipt(receipt, args.output)
        return 0
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        print(f"runtime benchmark attestation rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
