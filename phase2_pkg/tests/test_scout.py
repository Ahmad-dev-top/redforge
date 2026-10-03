import json
from pathlib import Path

from redforge.agents import run_scout
from redforge.sandbox.runner import SandboxResult
from redforge.schemas import AuditState, AuditStatus, ProjectKind, RepoMap

SLITHER_JSON = json.dumps({
    "success": True,
    "results": {"detectors": [{
        "check": "reentrancy-eth",
        "impact": "High",
        "confidence": "High",
        "description": "Reentrancy in Vault.withdraw",
        "elements": [{
            "type": "function", "name": "withdraw",
            "type_specific_fields": {"parent": {"name": "Vault"}},
            "source_mapping": {"filename_relative": "src/Vault.sol", "lines": [10]},
        }],
    }]},
})


class StubSandbox:
    """Returns canned Slither JSON; never touches Docker."""

    def run(self, command, repo_ro, workspace_rw):
        return SandboxResult(exit_code=0, stdout=SLITHER_JSON, stderr="", timed_out=False)


def _repo(tmp_path: Path) -> RepoMap:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text(
        "contract Vault { function withdraw(uint256 a) public {} }"
    )
    return RepoMap(
        root=str(tmp_path), kind=ProjectKind.FOUNDRY,
        contract_files=["src/Vault.sol"],
    )


def test_scout_attaches_findings_and_functions(tmp_path):
    state = AuditState(repo_url="x", run_id="t1", repo_map=_repo(tmp_path))
    update = run_scout(state, StubSandbox())
    assert update["status"] is AuditStatus.MAPPED
    assert len(update["findings"]) == 1
    assert update["findings"][0].detector == "reentrancy-eth"
    assert any(fn.function == "withdraw" for fn in update["functions"])


def test_scout_fails_without_repo_map():
    state = AuditState(repo_url="x", run_id="t2")
    update = run_scout(state, StubSandbox())
    assert update["status"] is AuditStatus.FAILED
