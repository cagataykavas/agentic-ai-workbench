#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.runtime_eval_attestation_checkpoint import (
    RuntimeBenchmarkCheckpointError,
    load_attestation_history_checkpoint,
    verify_attestation_history_checkpoint,
    verify_ed25519_signature,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify an independently retained runtime-benchmark history checkpoint."
    )
    parser.add_argument("history", type=Path)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--checkpoint-key-id", required=True)
    parser.add_argument("--checkpoint-public-key-sha256", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.history.resolve() == args.checkpoint.resolve():
            raise RuntimeBenchmarkCheckpointError("checkpoint_history_alias")
        receipt = verify_attestation_history_checkpoint(
            args.history,
            load_attestation_history_checkpoint(args.checkpoint),
            expected_source_revision=args.source_revision,
            expected_checkpoint_key_id=args.checkpoint_key_id,
            expected_public_key_sha256=args.checkpoint_public_key_sha256,
            signature_verifier=lambda public_key, signature, message: (
                verify_ed25519_signature(
                    public_key,
                    signature,
                    message,
                    executable=args.openssl,
                    timeout_seconds=args.timeout_seconds,
                )
            ),
        )
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        print(f"runtime benchmark history checkpoint rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, allow_nan=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
