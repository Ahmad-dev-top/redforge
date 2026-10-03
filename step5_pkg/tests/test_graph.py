from pathlib import Path

import pytest

from redforge.config import settings
from redforge.graph import build_graph
from redforge.llm import StubLLM
from redforge.schemas import AuditState, AuditStatus, ProjectKind, RepoMap
from tests.test_poc_engineer import FAIL_COMPILE, PASS_OUT, QueueSandbox

# Reuse stubs/fixtures from the agent tests.
from tests.test_scout import SLITHER_JSON

# Two hypotheses, both using the balance_increase oracle so PASS_OUT confirms
# whichever one is attempted. hyp-0 is finding-backed (HIGH x 0.9 -> 360),
# hyp-1 is agent-only (MEDIUM x 0.5 -> 150). Both clear the default floor (150).
STRAT2 = (
    '[{"finding_id":"slither-0","target_contract":"Vault","target_function":"withdraw",'
    '"vuln_class":"reentrancy","oracle":"balance_increase","rationale":"a"},'
    '{"finding_id":null,"target_contract":"Vault","target_function":"init",'
    '"vuln_class":"access_control","oracle":"balance_increase","rationale":"b"}]'
)


@pytest.fixture(autouse=True)
def _tmp_work(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "work_root", tmp_path / "work")


def _repo(tmp_path: Path) -> RepoMap:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text(
        "contract Vault { function withdraw(uint256 a) public {} function init() public {} }"
    )
    return RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY, contract_files=["src/Vault.sol"])


def _run(tmp_path, llm, sandbox, run_id):
    graph = build_graph(llm, sandbox, checkpointer=None)
    initial = AuditState(repo_url="x", run_id=run_id, repo_map=_repo(tmp_path))
    return AuditState.model_validate(graph.invoke(initial))


def test_no_hypotheses_ends_failed(tmp_path):
    # strategist returns [] -> FAILED -> route ends, poc never runs
    final = _run(tmp_path, StubLLM("[]"), QueueSandbox([SLITHER_JSON]), "g0")
    assert final.status is AuditStatus.FAILED
    assert final.vulnerabilities == []


def test_loop_stops_on_first_confirmation(tmp_path):
    llm = StubLLM([STRAT2, "poc test"])
    sandbox = QueueSandbox([SLITHER_JSON, PASS_OUT])  # scout, then poc attempt 1
    final = _run(tmp_path, llm, sandbox, "g1")
    assert final.status is AuditStatus.EXPLOIT_CONFIRMED
    assert len(final.vulnerabilities) == 1          # second hypothesis never attempted
    assert final.vulnerabilities[0].poc.oracle_confirmed is True
    assert sandbox.calls == 2 and len(llm.calls) == 2


def test_loop_advances_when_first_hypothesis_fails(tmp_path):
    n = settings.poc_max_retries
    llm = StubLLM([STRAT2] + ["t"] * n + ["t"])
    sandbox = QueueSandbox(
        [SLITHER_JSON] + [FAIL_COMPILE] * n + [PASS_OUT],
        exit_codes=[0] + [1] * n + [0],
    )
    final = _run(tmp_path, llm, sandbox, "g2")
    assert final.status is AuditStatus.EXPLOIT_CONFIRMED
    assert len(final.vulnerabilities) == 2          # first exhausted, second confirmed
    assert final.vulnerabilities[0].poc.oracle_confirmed is False
    assert final.vulnerabilities[1].poc.oracle_confirmed is True


def test_budget_cap_stops_the_loop(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "poc_max_hypotheses", 1)
    n = settings.poc_max_retries
    llm = StubLLM([STRAT2] + ["t"] * n)
    sandbox = QueueSandbox([SLITHER_JSON] + [FAIL_COMPILE] * n, exit_codes=[0] + [1] * n)
    final = _run(tmp_path, llm, sandbox, "g3")
    assert final.status is AuditStatus.HYPOTHESES_READY   # never confirmed
    assert len(final.vulnerabilities) == 1               # stopped at the cap
    assert sandbox.calls == 1 + n


def test_priority_floor_skips_everything(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "poc_priority_floor", 400)  # both hyps below -> no poc
    llm = StubLLM([STRAT2])
    sandbox = QueueSandbox([SLITHER_JSON])
    final = _run(tmp_path, llm, sandbox, "g4")
    assert final.status is AuditStatus.HYPOTHESES_READY
    assert final.vulnerabilities == []
    assert sandbox.calls == 1 and len(llm.calls) == 1        # poc never ran
