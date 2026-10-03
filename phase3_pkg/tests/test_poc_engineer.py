from pathlib import Path

import pytest

from redforge.agents import run_poc
from redforge.config import settings
from redforge.llm import StubLLM
from redforge.oracles import ORACLE_SENTINELS
from redforge.sandbox.runner import SandboxResult
from redforge.schemas import (
    AttackHypothesis,
    AuditState,
    AuditStatus,
    Finding,
    OracleType,
    ProjectKind,
    RepoMap,
    Severity,
    VulnClass,
)

SENTINEL = ORACLE_SENTINELS[OracleType.BALANCE_INCREASE]
PASS_OUT = f"[PASS] testExploit() (gas: 1)\n  {SENTINEL}\n"
FAIL_COMPILE = "Compiler run failed\nError: expected ';'"
FAIL_NO_SENTINEL = "[PASS] testExploit() (gas: 1)\n"  # passed but no proof emitted


class QueueSandbox:
    """Returns queued SandboxResults in order; records calls."""

    def __init__(self, outputs: list[str], exit_codes: list[int] | None = None):
        self.outputs = outputs
        self.exit_codes = exit_codes or [0] * len(outputs)
        self.calls = 0

    def run(self, command, repo_ro, workspace_rw):
        i = self.calls
        self.calls += 1
        return SandboxResult(
            exit_code=self.exit_codes[i], stdout=self.outputs[i], stderr="", timed_out=False
        )


def _state(tmp_path: Path) -> AuditState:
    (tmp_path / "Vault.sol").write_text(
        "contract Vault { function withdraw() public {} }"
    )
    return AuditState(
        repo_url="x", run_id="poc1",
        status=AuditStatus.HYPOTHESES_READY,
        repo_map=RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY, contract_files=["Vault.sol"]),
        findings=[Finding(id="slither-0", detector="reentrancy-eth",
                          vuln_class=VulnClass.REENTRANCY, severity=Severity.HIGH, confidence=0.9)],
        hypotheses=[AttackHypothesis(
            id="hyp-0", finding_id="slither-0", target_contract="Vault",
            target_function="withdraw", vuln_class=VulnClass.REENTRANCY,
            oracle=OracleType.BALANCE_INCREASE, rationale="reentrancy", priority=360,
        )],
    )


@pytest.fixture(autouse=True)
def _tmp_work(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "work_root", tmp_path / "work")


def test_confirmed_first_attempt(tmp_path):
    state = _state(tmp_path)
    update = run_poc(state, StubLLM("contract E {}"), QueueSandbox([PASS_OUT]))
    assert update["status"] is AuditStatus.EXPLOIT_CONFIRMED
    vuln = update["vulnerabilities"][0]
    assert vuln.poc.oracle_confirmed is True
    assert vuln.poc.attempt == 1
    assert update["token_cost_usd"] > 0


def test_self_corrects_then_confirms(tmp_path):
    state = _state(tmp_path)
    llm = StubLLM(["bad test", "fixed test"])
    sandbox = QueueSandbox([FAIL_COMPILE, PASS_OUT], exit_codes=[1, 0])
    update = run_poc(state, llm, sandbox)
    assert update["status"] is AuditStatus.EXPLOIT_CONFIRMED
    assert update["vulnerabilities"][0].poc.attempt == 2
    assert len(llm.calls) == 2
    assert sandbox.calls == 2


def test_passed_without_sentinel_is_not_confirmed(tmp_path):
    # forge test passes but the proof sentinel was never emitted -> never confirmed,
    # so the loop keeps self-correcting until retries are exhausted.
    state = _state(tmp_path)
    n = settings.poc_max_retries
    update = run_poc(state, StubLLM(["t"] * n), QueueSandbox([FAIL_NO_SENTINEL] * n))
    assert "status" not in update  # stays HYPOTHESES_READY (not set to CONFIRMED)
    assert update["vulnerabilities"][0].poc.oracle_confirmed is False


def test_exhausts_retries(tmp_path):
    state = _state(tmp_path)
    n = settings.poc_max_retries
    llm = StubLLM(["t"] * n)
    sandbox = QueueSandbox([FAIL_COMPILE] * n, exit_codes=[1] * n)
    update = run_poc(state, llm, sandbox)
    assert "status" not in update
    vuln = update["vulnerabilities"][0]
    assert vuln.poc.oracle_confirmed is False
    assert vuln.poc.attempt == n
    assert sandbox.calls == n


def test_nothing_to_do_without_hypotheses(tmp_path):
    state = _state(tmp_path)
    state.hypotheses = []
    assert run_poc(state, StubLLM("x"), QueueSandbox([PASS_OUT])) == {}


def test_extract_solidity_strips_language_tag():
    from redforge.agents.poc_engineer import _extract_solidity

    body = "contract E is Test {}"
    assert _extract_solidity(f"```solidity\n{body}\n```") == body
    assert _extract_solidity(f"```sol\n{body}\n```") == body          # was broken before
    assert _extract_solidity(f"```\n{body}\n```") == body
    assert _extract_solidity(body) == body                            # no fences


def test_next_hypothesis_skips_attempted_not_just_confirmed(tmp_path):
    # a prior FAILED attempt on hyp-0 must not be retried by the next call
    from redforge.agents.poc_engineer import _next_hypothesis

    state = _state(tmp_path)
    state.hypotheses.append(AttackHypothesis(
        id="hyp-1", finding_id=None, target_contract="Vault", target_function="init",
        vuln_class=VulnClass.ACCESS_CONTROL, oracle=OracleType.UNAUTHORIZED_STATE,
        rationale="x", priority=150,
    ))
    # record an exhausted (unconfirmed) attempt on hyp-0
    run_poc(state, StubLLM(["t"] * settings.poc_max_retries),
            QueueSandbox([FAIL_COMPILE] * settings.poc_max_retries,
                         exit_codes=[1] * settings.poc_max_retries))
    # simulate the state the graph loop would carry forward
    from redforge.schemas import PoCResult, Vulnerability
    state.vulnerabilities.append(Vulnerability(
        finding=state.findings[0], hypothesis=state.hypotheses[0],
        poc=PoCResult(hypothesis_id="hyp-0", attempt=3, oracle=OracleType.BALANCE_INCREASE),
    ))
    nxt = _next_hypothesis(state)
    assert nxt is not None and nxt.id == "hyp-1"
