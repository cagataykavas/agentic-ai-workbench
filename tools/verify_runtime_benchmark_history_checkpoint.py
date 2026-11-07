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
from src.runtime_eval_checkpoint_key_status import (
    GENESIS_STATUS_SHA256,
    load_checkpoint_key_status,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify an independently retained runtime-benchmark history checkpoint."
    )
    parser.add_argument("history", type=Path)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("checkpoint_key_status", type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--checkpoint-key-id", required=True)
    parser.add_argument("--checkpoint-public-key-sha256", required=True)
    parser.add_argument("--status-generation", type=int, default=1)
    parser.add_argument("--previous-status-sha256", default=GENESIS_STATUS_SHA256)
    parser.add_argument("--status-authority-key-id", required=True)
    parser.add_argument("--status-authority-public-key-sha256", required=True)
    parser.add_argument("--verification-time", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = {
            args.history.resolve(),
            args.checkpoint.resolve(),
            args.checkpoint_key_status.resolve(),
        }
        if len(inputs) != 3:
            raise RuntimeBenchmarkCheckpointError("checkpoint_input_alias")

        def verifier(public_key: bytes, signature: bytes, message: bytes) -> bool:
            return verify_ed25519_signature(
                public_key,
                signature,
                message,
                executable=args.openssl,
                timeout_seconds=args.timeout_seconds,
            )

        receipt = verify_attestation_history_checkpoint(
            args.history,
            load_attestation_history_checkpoint(args.checkpoint),
            load_checkpoint_key_status(args.checkpoint_key_status),
            expected_source_revision=args.source_revision,
            expected_checkpoint_key_id=args.checkpoint_key_id,
            expected_public_key_sha256=args.checkpoint_public_key_sha256,
            expected_status_generation=args.status_generation,
            expected_previous_status_sha256=args.previous_status_sha256,
            expected_status_authority_key_id=args.status_authority_key_id,
            expected_status_authority_public_key_sha256=(args.status_authority_public_key_sha256),
            verification_time=args.verification_time,
            signature_verifier=verifier,
            status_signature_verifier=verifier,
        )
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        print(f"runtime benchmark history checkpoint rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, allow_nan=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
