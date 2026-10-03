from pathlib import Path

import pytest

from redforge.agents import run_verification
from redforge.agents.verifier import _parse_halmos
from redforge.config import settings
from redforge.llm import StubLLM
from redforge.schemas import (
    AttackHypothesis,
    AuditState,
    AuditStatus,
    Finding,
    OracleType,
    Patch,
    PoCResult,
    ProjectKind,
    RepoMap,
    Severity,
    VulnClass,
    Vulnerability,
)
from tests.test_poc_engineer import QueueSandbox

REG_PASS = "Suite result: ok. 6 passed; 0 failed; 0 skipped\n"
DIFF_PASS = "[PASS] testLegit() (gas: 1)\nSuite result: ok. 1 passed; 0 failed\n"
HALMOS_PROVED = "[PASS] check_noLock() (paths: 24)\nSymbolic test result: 1 passed; 0 failed\n"
HALMOS_CEX = "[FAIL] check_noLock()\nCounterexample: amount=0x1 caller=0xbeef\n"
HALMOS_TIMEOUT = "halmos running...\n"  # paired with exit_code 124


@pytest.fixture(autouse=True)
def _tmp_work(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "work_root", tmp_path / "work")


def _state_patched(tmp_path: Path) -> AuditState:
    (tmp_path / "Vault.sol").write_text("contract Vault { function flashLoan() public {} }")
    finding = Finding(id="slither-0", detector="x", vuln_class=VulnClass.LOGIC,
                      severity=Severity.HIGH, confidence=0.9, file="Vault.sol")
    hyp = AttackHypothesis(id="hyp-0", finding_id="slither-0", target_contract="Vault",
                           target_function="flashLoan", vuln_class=VulnClass.LOGIC,
                           oracle=OracleType.FUNDS_LOCKED, rationale="r", priority=360)
    poc = PoCResult(hypothesis_id="hyp-0", attempt=1, oracle=OracleType.FUNDS_LOCKED,
                    oracle_confirmed=True, compiled=True, test_source="contract E {}")
    patch = Patch(finding_id="slither-0", contract="Vault", diff="--- a\n+++ b\n",
                  explanation="fix", compiles=True, poc_defeated=True, attempts=1,
                  patched_source="contract Vault { /* fixed */ }")
    vuln = Vulnerability(finding=finding, hypothesis=hyp, poc=poc, patch=patch)
    return AuditState(
        repo_url="x", run_id="ver1", status=AuditStatus.PATCHED,
        repo_map=RepoMap(root=str(tmp_path), kind=ProjectKind.FOUNDRY, contract_files=["Vault.sol"]),
        findings=[finding], hypotheses=[hyp], vulnerabilities=[vuln],
    )


def test_all_checks_pass_sets_verified(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    sandbox = QueueSandbox([REG_PASS, DIFF_PASS, HALMOS_PROVED], exit_codes=[0, 0, 0])
    update = run_verification(state, llm, sandbox)
    assert update["status"] is AuditStatus.VERIFIED
    r = update["vulnerabilities"][0].verification
    assert r.verified is True
    assert r.poc_now_fails and r.differential_equivalent and r.halmos_proved
    assert r.existing_tests_pass is True


def test_halmos_timeout_degrades_to_patched(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    # halmos times out: exit 124
    sandbox = QueueSandbox([REG_PASS, DIFF_PASS, HALMOS_TIMEOUT], exit_codes=[0, 0, 124])
    update = run_verification(state, llm, sandbox)
    assert "status" not in update  # stays PATCHED
    r = update["vulnerabilities"][0].verification
    assert r.verified is False
    assert r.halmos_timed_out is True and r.halmos_proved is False


def test_halmos_counterexample_not_verified(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    sandbox = QueueSandbox([REG_PASS, DIFF_PASS, HALMOS_CEX], exit_codes=[0, 0, 1])
    update = run_verification(state, llm, sandbox)
    assert "status" not in update
    r = update["vulnerabilities"][0].verification
    assert r.verified is False
    assert r.halmos_timed_out is False
    assert "Counterexample" in r.halmos_counterexample or "counterexample" in r.halmos_counterexample.lower()


def test_differential_failure_blocks_verified(tmp_path):
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    # differential test fails even though halmos would prove
    diff_fail = "[FAIL] testLegit()\n"
    sandbox = QueueSandbox([REG_PASS, diff_fail, HALMOS_PROVED], exit_codes=[0, 1, 0])
    update = run_verification(state, llm, sandbox)
    assert "status" not in update
    assert update["vulnerabilities"][0].verification.differential_equivalent is False


def test_regression_failure_does_not_block_verified(tmp_path):
    # CTF-style: existing tests fail (they assert the exploit), but differential +
    # halmos hold -> still VERIFIED, regression recorded as False.
    state = _state_patched(tmp_path)
    llm = StubLLM(["diff test", "halmos test"])
    reg_fail = "Suite result: FAILED. 2 passed; 1 failed\n"
    sandbox = QueueSandbox([reg_fail, DIFF_PASS, HALMOS_PROVED], exit_codes=[1, 0, 0])
    update = run_verification(state, llm, sandbox)
    assert update["status"] is AuditStatus.VERIFIED
    r = update["vulnerabilities"][0].verification
    assert r.existing_tests_pass is False and r.verified is True


def test_nothing_to_do_without_patch(tmp_path):
    state = _state_patched(tmp_path)
    state.vulnerabilities[0].patch.poc_defeated = False  # no successful patch
    assert run_verification(state, StubLLM("x"), QueueSandbox([REG_PASS])) == {}


def test_parse_halmos():
    assert _parse_halmos(HALMOS_PROVED, 0, False) == (True, "", False)
    proved, cex, to = _parse_halmos(HALMOS_CEX, 1, False)
    assert proved is False and "amount" in cex and to is False
    assert _parse_halmos("anything", 124, False)[2] is True   # timeout by exit code
    assert _parse_halmos("...timed out...", 0, False)[2] is True
