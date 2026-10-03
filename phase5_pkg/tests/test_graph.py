from pathlib import Path

import pytest

from redforge.config import settings
from redforge.graph import build_graph
from redforge.llm import StubLLM
from redforge.schemas import AuditState, AuditStatus, ProjectKind, RepoMap
from tests.test_poc_engineer import FAIL_COMPILE, PASS_OUT, QueueSandbox
from tests.test_remediation import EXPLOIT_DEFEATED

# Reuse stubs/fixtures from the agent tests.
from tests.test_scout import SLITHER_JSON
from tests.test_verifier import DIFF_PASS, HALMOS_PROVED, HALMOS_TIMEOUT, REG_PASS

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


def test_full_pipeline_reaches_verified(tmp_path):
    # scout, poc(confirm), remediation(patch), verification(reg, diff, halmos proved)
    llm = StubLLM([STRAT2, "poc test", "patched contract", "diff test", "halmos test"])
    sandbox = QueueSandbox(
        [SLITHER_JSON, PASS_OUT, EXPLOIT_DEFEATED, REG_PASS, DIFF_PASS, HALMOS_PROVED],
        exit_codes=[0, 0, 1, 0, 0, 0],
    )
    final = _run(tmp_path, llm, sandbox, "g1")
    assert final.status is AuditStatus.VERIFIED
    assert len(final.vulnerabilities) == 1          # second hypothesis never attempted
    v = final.vulnerabilities[0]
    assert v.poc.oracle_confirmed and v.patch.poc_defeated
    assert v.verification is not None and v.verification.verified is True


def test_confirmed_but_unpatchable_stays_confirmed(tmp_path):
    # poc confirms, but every patch leaves the exploit working -> run ends
    # EXPLOIT_CONFIRMED with an unpatched (recorded) vulnerability
    n = settings.remediation_max_retries
    llm = StubLLM([STRAT2, "poc test"] + ["patch"] * n)
    sandbox = QueueSandbox(
        [SLITHER_JSON, PASS_OUT] + [PASS_OUT] * n,  # exploit keeps succeeding post-patch
        exit_codes=[0, 0] + [0] * n,
    )
    final = _run(tmp_path, llm, sandbox, "g1b")
    assert final.status is AuditStatus.EXPLOIT_CONFIRMED
    v = final.vulnerabilities[0]
    assert v.patch is not None and v.patch.poc_defeated is False


def test_loop_advances_then_patches_but_halmos_times_out(tmp_path):
    # hyp0 fails x n, hyp1 confirms, patch lands, but halmos times out in
    # verification -> ends PATCHED (graceful degradation), not VERIFIED.
    n = settings.poc_max_retries
    llm = StubLLM([STRAT2] + ["t"] * n + ["t", "patch", "diff test", "halmos test"])
    sandbox = QueueSandbox(
        [SLITHER_JSON] + [FAIL_COMPILE] * n
        + [PASS_OUT, EXPLOIT_DEFEATED, REG_PASS, DIFF_PASS, HALMOS_TIMEOUT],
        exit_codes=[0] + [1] * n + [0, 1, 0, 0, 124],
    )
    final = _run(tmp_path, llm, sandbox, "g2")
    assert final.status is AuditStatus.PATCHED          # not VERIFIED (halmos undecided)
    assert len(final.vulnerabilities) == 2              # first exhausted, second confirmed
    v = final.vulnerabilities[1]
    assert v.poc.oracle_confirmed and v.patch.poc_defeated
    assert v.verification.halmos_timed_out is True and v.verification.verified is False


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
