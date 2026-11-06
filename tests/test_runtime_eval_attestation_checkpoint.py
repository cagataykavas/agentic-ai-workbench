from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.runtime_eval_attestation_checkpoint import (
    CHECKPOINT_SCHEMA,
    VERIFICATION_SCHEMA,
    RuntimeBenchmarkCheckpointError,
    create_attestation_history_checkpoint,
    load_attestation_history_checkpoint,
    verify_attestation_history_checkpoint,
)
from src.runtime_eval_attestation_history import append_attestation_acceptance
from tools.verify_runtime_benchmark_history_checkpoint import main

SOURCE_REVISION = "a" * 40
CHECKPOINT_KEY_ID = "runtime-benchmark-history-2026-11"
PUBLIC_KEY = b"k" * 44
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY).hexdigest()
SIGNATURE = b"s" * 64
ISSUED_AT = "2026-11-06T18:00:00Z"


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def receipt(seed: str) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "attestation_policy_sha256": seed * 64,
        "manifest_sha256": hashlib.sha256(seed.encode("ascii")).hexdigest(),
        "provenance_verified": True,
        "schema_version": "runtime-benchmark-attestation-verification/v1",
        "status": "pass",
        "verification_mode": "online",
    }
    return {**unsigned, "evidence_sha256": hashlib.sha256(canonical(unsigned)).hexdigest()}


def history(path: Path, count: int = 2) -> None:
    for seed in ("a", "b")[:count]:
        append_attestation_acceptance(path, receipt(seed))


def checkpoint(path: Path, **overrides: object) -> dict[str, object]:
    parameters = {
        "source_revision": SOURCE_REVISION,
        "checkpoint_key_id": CHECKPOINT_KEY_ID,
        "issued_at": ISSUED_AT,
        "public_key_der": PUBLIC_KEY,
        "signer": lambda message: SIGNATURE if message else b"",
    }
    parameters.update(overrides)
    return create_attestation_history_checkpoint(path, **parameters)


def verify(path: Path, document: object, **overrides: object) -> dict[str, object]:
    parameters = {
        "expected_source_revision": SOURCE_REVISION,
        "expected_checkpoint_key_id": CHECKPOINT_KEY_ID,
        "expected_public_key_sha256": PUBLIC_KEY_SHA256,
        "signature_verifier": lambda public_key, signature, message: (
            public_key == PUBLIC_KEY and signature == SIGNATURE and bool(message)
        ),
    }
    parameters.update(overrides)
    return verify_attestation_history_checkpoint(path, document, **parameters)


def test_verifies_checkpoint_and_emits_private_receipt(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    history(path)
    document = checkpoint(path)

    result = verify(path, document)

    assert document["checkpoint"]["schema_version"] == CHECKPOINT_SCHEMA
    assert result["schema_version"] == VERIFICATION_SCHEMA
    assert result["entry_count"] == 2
    assert result["head_entry_sha256"] == document["checkpoint"]["head_entry_sha256"]
    assert len(result["evidence_sha256"]) == 64
    serialized = json.dumps(result, sort_keys=True)
    assert SOURCE_REVISION not in serialized
    assert CHECKPOINT_KEY_ID not in serialized
    assert document["signature"]["value"] not in serialized
    assert document["public_key"]["value"] not in serialized


def test_detects_whole_history_rollback_or_replacement(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    history(path)
    document = checkpoint(path)

    path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
    with pytest.raises(RuntimeBenchmarkCheckpointError, match="history_mismatch"):
        verify(path, document)

    path.unlink()
    history(path, count=1)
    with pytest.raises(RuntimeBenchmarkCheckpointError, match="history_mismatch"):
        verify(path, document)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"expected_source_revision": "b" * 40}, "history_mismatch"),
        ({"expected_checkpoint_key_id": "replacement-key"}, "history_mismatch"),
        ({"expected_public_key_sha256": "f" * 64}, "public_key_mismatch"),
    ],
)
def test_rejects_source_or_key_substitution(
    tmp_path: Path, override: dict[str, object], message: str
) -> None:
    path = tmp_path / "history.jsonl"
    history(path)
    with pytest.raises(RuntimeBenchmarkCheckpointError, match=message):
        verify(path, checkpoint(path), **override)


def test_signature_is_checked_before_untrusted_checkpoint_semantics(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    history(path)
    document = copy.deepcopy(checkpoint(path))
    document["checkpoint"]["issued_at"] = "not-a-time"

    with pytest.raises(RuntimeBenchmarkCheckpointError, match="signature_invalid"):
        verify(path, document, signature_verifier=lambda *_: False)


def test_creation_rejects_empty_history_bad_time_and_bad_signer(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    path.write_text("", encoding="ascii")
    path.chmod(0o600)
    with pytest.raises(RuntimeBenchmarkCheckpointError, match="history_empty"):
        checkpoint(path)

    history(path)
    with pytest.raises(RuntimeBenchmarkCheckpointError, match="issued_at_invalid"):
        checkpoint(path, issued_at="2026-11-06T18:00:00+00:00")
    with pytest.raises(RuntimeBenchmarkCheckpointError, match="signature_invalid"):
        checkpoint(path, signer=lambda _: b"short")


def test_loader_rejects_duplicate_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"checkpoint":{},"checkpoint":{}}', encoding="utf-8")
    with pytest.raises(RuntimeBenchmarkCheckpointError, match="duplicate"):
        load_attestation_history_checkpoint(duplicate)

    path = tmp_path / "history.jsonl"
    history(path)
    target = tmp_path / "checkpoint.json"
    target.write_text(json.dumps(checkpoint(path)), encoding="utf-8")
    link = tmp_path / "checkpoint-link.json"
    link.symlink_to(target)
    with pytest.raises(RuntimeBenchmarkCheckpointError, match="file_unavailable"):
        load_attestation_history_checkpoint(link)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is unavailable")
def test_real_ed25519_signature_and_cli_verification(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.der"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )

    def sign(message: bytes) -> bytes:
        message_path = tmp_path / "message.bin"
        signature_path = tmp_path / "signature.bin"
        message_path.write_bytes(message)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(message_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )
        return signature_path.read_bytes()

    history_path = tmp_path / "history.jsonl"
    history(history_path)
    public_key_der = public_key.read_bytes()
    document = checkpoint(history_path, public_key_der=public_key_der, signer=sign)
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(json.dumps(document), encoding="utf-8")

    assert (
        main(
            [
                str(history_path),
                str(checkpoint_path),
                "--source-revision",
                SOURCE_REVISION,
                "--checkpoint-key-id",
                CHECKPOINT_KEY_ID,
                "--checkpoint-public-key-sha256",
                hashlib.sha256(public_key_der).hexdigest(),
            ]
        )
        == 0
    )

    document["signature"]["value"] = base64.b64encode(b"x" * 64).decode("ascii")
    checkpoint_path.write_text(json.dumps(document), encoding="utf-8")
    assert (
        main(
            [
                str(history_path),
                str(checkpoint_path),
                "--source-revision",
                SOURCE_REVISION,
                "--checkpoint-key-id",
                CHECKPOINT_KEY_ID,
                "--checkpoint-public-key-sha256",
                hashlib.sha256(public_key_der).hexdigest(),
            ]
        )
        == 2
    )
