from pathlib import Path

ROOT = Path(__file__).parents[1]
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
SIGNER = (ROOT / ".github/workflows/attest-failover-evidence.yml").read_text(encoding="utf-8")


def test_failover_job_cannot_mint_attestations_directly() -> None:
    failover = CI.split("  postgres-failover:\n", 1)[1].split("  attest-failover-evidence:\n", 1)[0]

    assert "attestations: write" not in failover
    assert "id-token: write" not in failover
    assert "actions/attest@" not in failover
    assert "name: postgres-authority-failover-evidence" in failover


def test_signer_is_default_branch_only_reusable_workflow() -> None:
    caller = CI.split("  attest-failover-evidence:\n", 1)[1]

    assert "github.event_name == 'push' && github.ref == 'refs/heads/main'" in caller
    assert "needs: postgres-failover" in caller
    assert "uses: ./.github/workflows/attest-failover-evidence.yml" in caller
    assert "attestations: write" in caller
    assert "id-token: write" in caller


def test_reusable_signer_reaudits_before_attesting() -> None:
    assert "workflow_call:" in SIGNER
    assert "environment: failover-evidence-signer" in SIGNER
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in SIGNER
    assert "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6" in SIGNER
    assert "name: postgres-authority-failover-evidence" in SIGNER
    assert SIGNER.index("Re-audit evidence inside signer boundary") < SIGNER.index("Attest audited evidence")
    assert "--prepared-evidence .artifacts/postgres-failover-prepared.json" in SIGNER
    assert "--verified-evidence .artifacts/postgres-failover-verified.json" in SIGNER
