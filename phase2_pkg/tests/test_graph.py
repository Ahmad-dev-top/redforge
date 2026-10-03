from pathlib import Path

from redforge.graph import build_graph
from redforge.llm import StubLLM
from redforge.schemas import AuditState, AuditStatus, ProjectKind, RepoMap

# Reuse the stubs from the agent tests.
from tests.test_scout import StubSandbox
from tests.test_strategist import GOOD


def _repo(tmp_path: Path) -> RepoMap:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text(
        "contract Vault { function withdraw(uint256 a) public {} }"
    )
    return RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY, contract_files=["src/Vault.sol"])


def test_graph_runs_scout_then_strategist(tmp_path):
    graph = build_graph(StubLLM(GOOD), StubSandbox(), checkpointer=None)
    initial = AuditState(repo_url="x", run_id="g1", repo_map=_repo(tmp_path))
    final = AuditState.model_validate(graph.invoke(initial))
    assert final.status is AuditStatus.HYPOTHESES_READY
    assert len(final.findings) == 1
    assert len(final.hypotheses) == 2
    assert final.token_cost_usd > 0


def test_graph_no_hypotheses_is_failed(tmp_path):
    graph = build_graph(StubLLM("[]"), StubSandbox(), checkpointer=None)
    initial = AuditState(repo_url="x", run_id="g2", repo_map=_repo(tmp_path))
    final = AuditState.model_validate(graph.invoke(initial))
    assert final.status is AuditStatus.FAILED
    assert final.hypotheses == []
